package pii

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/proc"
	"github.com/yetone/magpie/internal/redact"
)

const externalPrefix = "external/"

// externalLaunch holds what can change the results of the helper.
type externalLaunch struct {
	Command         string
	Args            []string
	Dir             string
	Weights         string
	WeightsRevision string
	PackageRevision string
}

func newExternalModel(id, identity string, launch externalLaunch) *externalModel {
	m := &externalModel{id: id, identity: identity, launch: launch, run: make(chan struct{})}
	path := filepath.Join(appdir.Cache(), "external-privacy", "found-"+identity+".bin")
	m.backend = &backend{
		turn: make(chan struct{}, 1), waiting: new(atomic.Int32),
		cache: newLRU(20000), disk: new(diskState), chunk: guardChunk,
		path:     func() string { return path },
		heldBack: func() error { return nil },
	}
	return m
}

// IsExternal includes a saved selection whose external model is now missing.
func IsExternal(id string) bool { return strings.HasPrefix(id, externalPrefix) }

func ExternalIdentity(m Model) string {
	if external, ok := m.(*externalModel); ok {
		return external.identity
	}
	return ""
}

type externalModel struct {
	id       string
	identity string
	launch   externalLaunch
	backend  *backend
	retired  atomic.Bool

	mu       sync.Mutex
	name     string
	minScore float64
	helper   *helper
	run      chan struct{} // closed by Stop, including for work still in the queue
	idle     *time.Timer
	loading  bool
	failed   string
}

func (m *externalModel) ID() string      { return m.id }
func (m *externalModel) Supported() bool { return m.backend != nil }
func (m *externalModel) Size() int64     { return 0 }
func (m *externalModel) Cancel()         {}

func (m *externalModel) setMetadata(name string, minScore float64) {
	m.mu.Lock()
	m.name, m.minScore = name, minScore
	m.mu.Unlock()
}

func (m *externalModel) MinScore() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.minScore
}

func (m *externalModel) Installed() bool {
	if !m.Supported() || m.retired.Load() {
		return false
	}
	if _, err := os.Stat(m.launch.Weights); err != nil {
		return false
	}
	_, err := exec.LookPath(m.launch.Command)
	return err == nil
}

func (m *externalModel) unavailable() error {
	return fmt.Errorf("privacy model %q is unavailable, select a model from an enabled plugin with local weights and a launcher", m.id)
}

func (m *externalModel) Download(func()) error { return m.unavailable() }

func (m *externalModel) Find(ctx context.Context, texts []string) ([][]redact.Found, error) {
	run := m.currentRun()
	if !m.Installed() {
		return nil, m.unavailable()
	}
	return m.backend.findWith(ctx, texts, m.classifier(run))
}

func (m *externalModel) Now() Status {
	installed := m.Installed()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{Model: m.id, Name: m.name, External: true, Supported: m.Supported(), Installed: installed}
	if !s.Installed {
		s.Failed = m.unavailable().Error()
		return s
	}
	s.Waiting = int(m.backend.waiting.Load())
	s.Failed, s.Loading = m.failed, m.loading
	if h := m.helper; h != nil {
		select {
		case <-h.exited:
		default:
			s.Running, s.Device, s.GPU, s.LoadMS = true, h.hello.Device, h.hello.GPU, h.hello.MS
		}
	}
	return s
}

func (m *externalModel) Warm() {
	run := m.currentRun()
	if m.Installed() {
		go func() {
			select {
			case <-run:
				return
			case m.backend.turn <- struct{}{}:
			}
			defer func() { <-m.backend.turn }()
			classifySafely(m.classifier(run), []string{"warm"})
		}()
	}
}

func (m *externalModel) currentRun() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.run
}

func (m *externalModel) Stop() {
	m.mu.Lock()
	if m.run != nil {
		close(m.run)
		m.run = make(chan struct{})
	}
	h := m.detach()
	m.loading, m.failed = false, ""
	m.mu.Unlock()
	if h != nil {
		h.kill()
	}
}

// The command and model files belong to the user.
func (m *externalModel) Remove() error {
	m.Stop()
	return nil
}

func (m *externalModel) detach() *helper {
	if m.idle != nil {
		m.idle.Stop()
		m.idle = nil
	}
	h := m.helper
	m.helper = nil
	return h
}

func (m *externalModel) idleStop(h *helper) {
	select {
	case m.backend.turn <- struct{}{}:
		defer func() { <-m.backend.turn }()
	default:
		return
	}
	m.mu.Lock()
	if m.helper != h {
		m.mu.Unlock()
		return
	}
	m.detach()
	m.mu.Unlock()
	end(h)
}

func (m *externalModel) start(run <-chan struct{}) (*helper, error) {
	m.mu.Lock()
	if m.retired.Load() || run != m.run {
		m.mu.Unlock()
		return nil, errStopped
	}
	if h := m.helper; h != nil {
		m.mu.Unlock()
		return h, nil
	}
	m.loading = true
	m.mu.Unlock()

	args := append(slices.Clone(m.launch.Args), m.launch.Weights)
	cmd := proc.Command(m.launch.Command, args...)
	cmd.Dir = m.launch.Dir
	h, err := startHelper(cmd, loadTimeout, "", run)
	m.mu.Lock()
	if m.run != run {
		m.mu.Unlock()
		if h != nil {
			h.kill()
		}
		return nil, errStopped
	}
	m.loading = false
	if err != nil {
		m.failed = err.Error()
	} else {
		m.helper, m.failed = h, ""
	}
	m.mu.Unlock()
	return h, err
}

func (m *externalModel) classifier(run <-chan struct{}) func([]string) ([][]redact.Found, error) {
	return func(texts []string) ([][]redact.Found, error) {
		return m.classify(run, texts)
	}
}

func (m *externalModel) classify(run <-chan struct{}, texts []string) ([][]redact.Found, error) {
	h, err := m.start(run)
	if err != nil {
		return nil, err
	}
	found, err := h.classify(texts)
	if err == nil {
		for i, spans := range found {
			for _, f := range spans {
				if f.Start < 0 || f.End > len(texts[i]) || f.Start >= f.End ||
					!utf8.ValidString(texts[i][f.Start:f.End]) || !(f.Score >= 0 && f.Score <= 1) {
					err = errors.New("invalid detection span")
					break
				}
			}
		}
	}
	m.mu.Lock()
	if m.helper != h {
		m.mu.Unlock()
		return nil, errStopped
	}
	if err == nil {
		if m.idle != nil {
			m.idle.Stop()
		}
		m.idle = time.AfterFunc(idleAfter, func() { m.idleStop(h) })
		m.mu.Unlock()
		// Cache writes are best effort, as with the built-in models.
		_ = os.MkdirAll(filepath.Dir(m.backend.path()), 0o700)
		return found, nil
	}
	m.detach()
	// An external program can include request text in its errors.
	m.failed = "the external masking model returned an error or an invalid response"
	message := m.failed
	m.mu.Unlock()
	h.kill()
	return nil, errors.New(message)
}
