package pii

import (
	"fmt"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/redact"
)

// helperRunner owns one model subprocess. Its turn channel also belongs
// to the inference backend. The state lock never spans process I/O.
type helperRunner struct {
	turn              chan struct{}
	retry             func(error, int) time.Duration
	backoffBeforeLoad bool

	mu      sync.Mutex
	startMu sync.Mutex
	h       *helper
	run     chan struct{}
	idle    *time.Timer
	idleSeq uint64
	loading bool
	failed  string
	lastErr error
	fails   int
	retryAt time.Time
}

func (r *helperRunner) currentRun() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run == nil {
		r.run = make(chan struct{})
	}
	return r.run
}

func (r *helperRunner) load(run <-chan struct{}, start func(<-chan struct{}) (*helper, error)) (*helper, error) {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	r.mu.Lock()
	switch {
	case run != r.run:
		r.mu.Unlock()
		return nil, errStopped
	case r.h != nil:
		h := r.h
		r.mu.Unlock()
		return h, nil
	}
	if r.backoffBeforeLoad {
		if err := r.heldBackLocked(); err != nil {
			r.mu.Unlock()
			return nil, err
		}
	}
	r.loading = true
	r.mu.Unlock()

	h, err := start(run)
	r.mu.Lock()
	if r.run != run {
		r.mu.Unlock()
		if h != nil {
			h.kill()
		}
		return nil, errStopped
	}
	r.loading = false
	if err != nil {
		r.failLocked(err)
	} else {
		r.h = h
		r.failed = ""
	}
	r.mu.Unlock()
	return h, err
}

func (r *helperRunner) complete(run <-chan struct{}, h *helper, err error, requestOnly bool) error {
	r.mu.Lock()
	if run != r.run {
		r.mu.Unlock()
		return errStopped
	}
	var gone *helper
	if r.h == h {
		if err == nil || requestOnly {
			if err == nil {
				r.clearFailureLocked()
			}
			r.resetIdleLocked(h)
		} else {
			gone = r.detachLocked()
			r.failLocked(err)
		}
	}
	r.mu.Unlock()
	if gone != nil {
		gone.kill()
	}
	return err
}

func (r *helperRunner) stop(gracefulIfIdle bool) {
	idle := false
	if gracefulIfIdle {
		n := r.tryReserve()
		defer r.release(n)
		idle = n == cap(r.turn)
	}
	r.mu.Lock()
	h := r.detachLocked()
	if r.run != nil {
		close(r.run)
		r.run = nil
	}
	r.loading = false
	r.clearFailureLocked()
	r.mu.Unlock()
	if idle {
		end(h)
	} else if h != nil {
		h.kill()
	}
}

func (r *helperRunner) detachLocked() *helper {
	if r.idle != nil {
		r.idle.Stop()
		r.idle = nil
	}
	h := r.h
	r.h = nil
	return h
}

func (r *helperRunner) resetIdleLocked(h *helper) {
	if r.idle != nil {
		r.idle.Stop()
	}
	r.idleSeq++
	seq := r.idleSeq
	r.idle = time.AfterFunc(idleAfter, func() { r.expireIdle(h, seq) })
}

func (r *helperRunner) expireIdle(h *helper, seq uint64) {
	n := r.tryReserve()
	defer r.release(n)
	if n != cap(r.turn) {
		return
	}
	r.mu.Lock()
	var gone *helper
	if r.h == h && r.idleSeq == seq {
		gone = r.detachLocked()
	}
	r.mu.Unlock()
	end(gone)
}

func (r *helperRunner) tryReserve() int {
	for n := 0; n < cap(r.turn); n++ {
		select {
		case r.turn <- struct{}{}:
		default:
			return n
		}
	}
	return cap(r.turn)
}

func (r *helperRunner) release(n int) {
	for range n {
		<-r.turn
	}
}

func (r *helperRunner) warm(run <-chan struct{}, classify func([]string) ([][]redact.Found, error)) {
	go func() {
		select {
		case <-run:
			return
		case r.turn <- struct{}{}:
		}
		defer r.release(1)
		classifySafely(classify, []string{"warm"})
	}()
}

func (r *helperRunner) fillStatusLocked(s *Status) {
	if h := r.h; h != nil {
		select {
		case <-h.exited:
		default:
			info := h.device()
			s.Running, s.Device, s.GPU, s.LoadMS, s.GPUError = true, info.Device, info.GPU, info.MS, info.GPUError
		}
	}
	s.Failed, s.Loading = r.failed, r.loading
}

func (r *helperRunner) clearFailureLocked() {
	r.failed, r.lastErr, r.fails, r.retryAt = "", nil, 0, time.Time{}
}

func (r *helperRunner) failLocked(err error) {
	r.failed = err.Error()
	if r.retry != nil {
		if delay := r.retry(err, r.fails+1); delay > 0 {
			r.lastErr, r.fails, r.retryAt = err, r.fails+1, time.Now().Add(delay)
		}
	}
}

func (r *helperRunner) heldBack() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.heldBackLocked()
}

func (r *helperRunner) heldBackLocked() error {
	if r.lastErr == nil || !time.Now().Before(r.retryAt) {
		return nil
	}
	return fmt.Errorf("%w; it is tried again in %s, and until then a request it hasn't read is held back at once. To send requests masked by the rules alone, turn the model off in Settings → Privacy",
		r.lastErr, time.Until(r.retryAt).Round(time.Second))
}
