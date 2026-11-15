package pii

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/lazyre"
	"github.com/yetone/magpie/internal/proc"
	"github.com/yetone/magpie/internal/redact"
)

const externalPrefix = "external/"

type externalSpec struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Command  string   `json:"command"`
	Args     []string `json:"args,omitempty"`
	Revision string   `json:"revision,omitempty"`
	MinScore float64  `json:"minScore,omitempty"`
}

var externalID = lazyre.New(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// The config is local to this process and never travels with synced settings.
var externalModels = sync.OnceValue(func() []Model {
	models, err := loadExternalModels(filepath.Join(appdir.Config(), "privacy-models.json"), appdir.Cache())
	if err != nil {
		log.Printf("privacy models: %v", err)
	}
	return models
})

func loadExternalModels(path, cacheDir string) ([]Model, error) {
	const limit = 64 << 10
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s: file exceeds %d bytes", path, limit)
	}
	var cfg struct {
		Models []externalSpec `json:"externalPrivacyModels"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("%s: expected one JSON object", path)
	}
	var out []Model
	seen := map[string]bool{}
	for i, spec := range cfg.Models {
		if !externalID.MatchString(spec.ID) || seen[spec.ID] || strings.TrimSpace(spec.Name) == "" ||
			!filepath.IsAbs(spec.Command) || spec.MinScore < 0 || spec.MinScore >= 1 {
			return nil, fmt.Errorf("%s: invalid or duplicate external model at index %d", path, i)
		}
		seen[spec.ID] = true
		data, err := json.Marshal(spec)
		if err != nil {
			return nil, err
		}
		id := fmt.Sprintf("%x", sha256.Sum256(data))
		m := &externalModel{spec: spec, id: externalPrefix + spec.ID, identity: id}
		dir := filepath.Join(cacheDir, "external-privacy")
		m.backend = &backend{
			turn: make(chan struct{}, 1), waiting: new(atomic.Int32),
			cache: newLRU(20000), disk: new(diskState), chunk: guardChunk,
			path:     func() string { return filepath.Join(dir, "found-"+id+".bin") },
			classify: m.classify, heldBack: func() error { return nil },
		}
		out = append(out, m)
	}
	return out, nil
}

func IsExternal(id string) bool { return strings.HasPrefix(id, externalPrefix) }

func ExternalIdentity(m Model) string {
	if external, ok := m.(*externalModel); ok {
		return external.identity
	}
	return ""
}

type externalModel struct {
	spec     externalSpec
	id       string
	identity string
	backend  *backend

	mu      sync.Mutex
	helper  *helper
	stop    chan struct{}
	idle    *time.Timer
	loading bool
	failed  string
}

func (m *externalModel) ID() string        { return m.id }
func (m *externalModel) Supported() bool   { return m.backend != nil }
func (m *externalModel) Size() int64       { return 0 }
func (m *externalModel) MinScore() float64 { return m.spec.MinScore }
func (m *externalModel) Cancel()           {}

func (m *externalModel) Installed() bool {
	_, err := exec.LookPath(m.spec.Command)
	return m.Supported() && err == nil
}

func (m *externalModel) unavailable() error {
	return fmt.Errorf("external masking model %q is unavailable, check privacy-models.json and its local command", m.id)
}

func (m *externalModel) Download(func()) error { return m.unavailable() }

func (m *externalModel) Find(ctx context.Context, texts []string) ([][]redact.Found, error) {
	if !m.Installed() {
		return nil, m.unavailable()
	}
	return m.backend.find(ctx, texts)
}

func (m *externalModel) Now() Status {
	s := Status{Model: m.id, Name: m.spec.Name, External: true, Supported: m.Supported(), Installed: m.Installed()}
	if !s.Installed {
		s.Failed = m.unavailable().Error()
		return s
	}
	s.Waiting = int(m.backend.waiting.Load())
	m.mu.Lock()
	defer m.mu.Unlock()
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
	if m.Installed() {
		go func() {
			m.backend.turn <- struct{}{}
			defer func() { <-m.backend.turn }()
			classifySafely(m.classify, []string{"warm"})
		}()
	}
}

func (m *externalModel) Stop() {
	m.mu.Lock()
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
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

func (m *externalModel) start() (*helper, error) {
	m.mu.Lock()
	if h := m.helper; h != nil {
		m.mu.Unlock()
		return h, nil
	}
	stop := make(chan struct{})
	m.stop, m.loading = stop, true
	m.mu.Unlock()

	h, err := startHelper(proc.Command(m.spec.Command, m.spec.Args...), loadTimeout, "", stop)
	m.mu.Lock()
	if m.stop != stop {
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

func (m *externalModel) classify(texts []string) ([][]redact.Found, error) {
	h, err := m.start()
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
