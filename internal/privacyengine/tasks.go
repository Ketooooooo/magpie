package privacyengine

import (
	"container/list"
	"net/http"
	"sync"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/privacyengine/internal/redact"
)

// Tasks remembers the request's engine and placeholders while its asynchronous
// job can still be polled. Missing and unsupported jobs leave values masked.
type Tasks struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	recent  list.List
}

type task struct {
	key     string
	allowed map[string]struct{}
}

const (
	maxTasks            = 512
	maxTaskPlaceholders = 512
)

func (t *Tasks) Remember(key, engine string, hits []gwmw.Hit) {
	if key == "" || len(hits) == 0 {
		return
	}
	var allowed map[string]struct{}
	if engine == Builtin {
		allowed = make(map[string]struct{}, min(len(hits), maxTaskPlaceholders))
		for _, hit := range hits {
			if hit.Action == "" && hit.Placeholder != "" {
				allowed[hit.Placeholder] = struct{}{}
				if len(allowed) == maxTaskPlaceholders {
					break
				}
			}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make(map[string]*list.Element)
	}
	if previous := t.entries[key]; previous != nil {
		t.recent.Remove(previous)
	}
	t.entries[key] = t.recent.PushFront(task{key: key, allowed: allowed})
	if t.recent.Len() > maxTasks {
		old := t.recent.Back()
		delete(t.entries, old.Value.(task).key)
		t.recent.Remove(old)
	}
}

func (t *Tasks) WrapReply(w http.ResponseWriter, key string) (http.ResponseWriter, func()) {
	t.mu.Lock()
	var allowed map[string]struct{}
	if e := t.entries[key]; e != nil {
		t.recent.MoveToFront(e)
		allowed = e.Value.(task).allowed
	}
	t.mu.Unlock()
	if len(allowed) == 0 {
		return w, func() {}
	}
	rw := redact.NewScopedWriter(w, allowed)
	return rw, rw.Finish
}
