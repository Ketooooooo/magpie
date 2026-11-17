package pii

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/pii/guard"
	"github.com/yetone/magpie/internal/redact"
)

// AstrLink Guard (QuantumNous/astrlink-guard, Apache-2.0) is the second
// local model: a 37 MB int8 token classifier for Chinese and English,
// run by a Magpie helper using internal/pii/guard, on the CPU of every
// system and through CoreML on a Mac, with no separate executable to download. Its files are fetched from
// Hugging Face at the revision their sha256 were pinned at (the
// publisher's own listing), and are loaded on the first request that
// needs them and let go after idleAfter with none.

// guardRev is the repo's revision (v0.1.3) the files below were hashed at.
var guardRev = "7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4"

type pinned struct {
	path string // in the repo; saved under its base name
	size int64
	sha  string
}

var guardFiles = []pinned{
	{"int8/model_int8.onnx", 330781, "0a070d3113615e33ba3b84d6bd486f663a377c04c4b056e7381732179f51832a"},
	{"int8/model_int8.onnx_data", 37124608, "0ba34216ceead01e0ae2dfd8e46d52b67e7aee80b04f722d9b758613a91c0067"},
	{"int8/tokenizer.json", 1502881, "0cf3b235ef125658015a6c8026a5fe6f28088bf825101a990ec18a10200feef4"},
}

var guardBase = "https://huggingface.co/QuantumNous/astrlink-guard/resolve/"

func guardURL(f pinned) string { return guardBase + guardRev + "/" + f.path }

// guardRoot is where AstrLink Guard's files are kept, in magpie's cache
// beside Privacy Filter's folder: a folder per revision, and the found
// file (cache.go).
var guardRoot = func() string { return filepath.Join(appdir.Cache(), "astrlink-guard") }

func guardDir() string { return filepath.Join(guardRoot(), guardRev[:12]) }

func guardSize() int64 {
	var n int64
	for _, f := range guardFiles {
		n += f.size
	}
	return n
}

// guardInstalled says every file is on disk at its size.
func guardInstalled() bool {
	for _, f := range guardFiles {
		fi, err := os.Stat(filepath.Join(guardDir(), filepath.Base(f.path)))
		if err != nil || fi.Size() != f.size {
			return false
		}
	}
	return true
}

var gdl dlState

// guardInstall fetches the files not on disk yet, each checked against
// its sha256; done counts the bytes of all three.
func guardInstall(ctx context.Context) error {
	if err := os.MkdirAll(guardDir(), 0o755); err != nil {
		return err
	}
	var base int64
	for _, f := range guardFiles {
		path := filepath.Join(guardDir(), filepath.Base(f.path))
		if fi, err := os.Stat(path); err != nil || fi.Size() != f.size {
			var n atomic.Int64
			stop := make(chan struct{})
			go func() {
				t := time.NewTicker(200 * time.Millisecond)
				defer t.Stop()
				for {
					select {
					case <-stop:
						return
					case <-t.C:
						gdl.done.Store(base + n.Load())
					}
				}
			}()
			err := fetch(ctx, guardURL(f), path, f.size, f.sha, &n)
			close(stop)
			if err != nil {
				return fmt.Errorf("downloading %s: %w", filepath.Base(f.path), err)
			}
		}
		base += f.size
		gdl.done.Store(base)
	}
	removeOldGuard()
	return nil
}

// removeOldGuard deletes the folders of revisions pinned before.
func removeOldGuard() {
	es, _ := os.ReadDir(guardRoot())
	for _, e := range es {
		if e.IsDir() && e.Name() != filepath.Base(guardDir()) {
			os.RemoveAll(filepath.Join(guardRoot(), e.Name()))
		}
	}
}

var gsrv = helperRunner{
	turn:              guardTurn,
	backoffBeforeLoad: true,
	retry: func(err error, n int) time.Duration {
		if err == ErrNotInstalled {
			return 0
		}
		return retryAfter(n)
	},
}

var guardStart = startAstrLink

// guardTurn is held by each request the model reads, guard.Cores() of
// them at once. They share those cores (guard.Find takes them as it reads
// each window), so a short request goes beside a long one's chunk on a
// core of its own instead of after it, and requests at once never read
// on more cores than one did. One at a time, concurrent agent requests
// queued behind each other (yyhhyyyyyy on Discord, 10-28). Through
// CoreML they meet at its one model, which reads as fast for one
// request as for eight.
var guardTurn = make(chan struct{}, guard.Cores())

var guardBackend = &backend{
	turn:     guardTurn,
	waiting:  new(atomic.Int32),
	cache:    newLRU(20000),
	disk:     new(diskState),
	path:     func() string { return filepath.Join(guardRoot(), "found-"+guardRev[:12]+".bin") },
	heldBack: gsrv.heldBack,
	chunk:    guardChunk,
}

func guardClassifier(run <-chan struct{}) func([]string) ([][]redact.Found, error) {
	return func(texts []string) ([][]redact.Found, error) {
		h, err := gsrv.load(run, launchGuard)
		if err != nil {
			return nil, err
		}
		found, err := h.classify(texts)
		_, requestOnly := err.(requestError)
		if err := gsrv.complete(run, h, err, requestOnly); err != nil {
			return nil, err
		}
		return found, nil
	}
}

func launchGuard(stop <-chan struct{}) (*helper, error) {
	if !guardInstalled() {
		return nil, ErrNotInstalled
	}
	return guardStart(stop)
}

// guardLabels names the model's labels as Privacy Filter does, which is
// what redact's Model reads: url, ip_address and private_date are left
// out there as they are for Privacy Filter (an address the rules don't
// mask is in a request for the vendor to read).
var guardLabels = map[string]string{
	"private_person":  "private_person",
	"private_address": "private_address",
	"phone":           "private_phone",
	"email":           "private_email",
	"account":         "account_number",
	"payment_card":    "account_number",
	"common_secret":   "secret",
	"url":             "private_url",
	"ip_address":      "ip_address",
	"private_date":    "private_date",
}

func guardLabel(l string) string {
	if n, ok := guardLabels[l]; ok {
		return n
	}
	return l
}

// guardModel is AstrLink Guard as a Model.
type guardModel struct{}

func (guardModel) ID() string { return AstrLinkGuard }

func (guardModel) ManagesWeights() bool { return true }

func (guardModel) Generation() string { return "" }

func (guardModel) Supported() bool { return true }

func (guardModel) Installed() bool { return guardInstalled() }

func (guardModel) Size() int64 { return guardSize() }

func (guardModel) MinScore() float64 { return guard.MinScore }

func (guardModel) Find(ctx context.Context, texts []string) ([][]redact.Found, error) {
	return guardBackend.findWith(ctx, texts, guardClassifier(gsrv.currentRun()))
}

func (guardModel) Now() Status {
	s := Status{Model: AstrLinkGuard, ManagedWeights: true, Supported: true, Installed: guardInstalled(), Size: guardSize(), Rosetta: translated()}
	gdl.fill(&s)
	gsrv.mu.Lock()
	gsrv.fillStatusLocked(&s)
	gsrv.mu.Unlock()
	s.Waiting = int(guardBackend.waiting.Load())
	return s
}

func (guardModel) Download(done func()) error { return gdl.run(guardSize(), guardInstall, done) }

func (guardModel) Cancel() { gdl.stop() }

func (guardModel) Warm() {
	if guardInstalled() {
		run := gsrv.currentRun()
		gsrv.warm(run, guardClassifier(run))
	}
}

func (guardModel) Stop() { gsrv.stop(false) }

func (g guardModel) Remove() error {
	g.Cancel()
	g.Stop()
	gdl.mu.Lock()
	gdl.err = ""
	gdl.mu.Unlock()
	return os.RemoveAll(guardRoot())
}
