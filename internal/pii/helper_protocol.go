package pii

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/yetone/magpie/internal/redact"
)

const helperProtocol = 2

type pipeCall struct {
	texts []string
	reply chan pipeReply
}

type pipeReply struct {
	found [][]redact.Found
	err   error
}

// A version 2 reply starts with the request ID and the length of an
// optional JSON device update, followed by the original result payload.
// IDs let a worker answer in completion order when it reads in parallel.
type replyPipe struct {
	next   atomic.Uint32
	calls  sync.Map // uint32 -> *pipeCall
	device atomic.Pointer[hello]
	done   chan struct{}
	err    error // published by closing done
}

func (h *helper) startReplyPipe() {
	p := &replyPipe{done: make(chan struct{})}
	p.device.Store(&h.hello)
	h.replies = p
	go func() {
		p.err = h.readReplies()
		close(p.done)
		h.kill()
	}()
}

func (h *helper) readReplies() error {
	r := &reader{r: h.out}
	for {
		id := r.u32()
		if r.err != nil {
			return r.fail(h)
		}
		entry, ok := h.replies.calls.Load(id)
		if !ok {
			return fmt.Errorf("unexpected reply to request %d", id)
		}
		n := r.u32()
		if n > 64<<10 {
			return fmt.Errorf("invalid helper device update length %d", n)
		}
		if n != 0 {
			var status hello
			data := r.bytes(int(n))
			if r.err != nil {
				return r.fail(h)
			}
			if err := json.Unmarshal(data, &status); err != nil {
				return err
			}
			if status.Device == "" && status.Via == "" {
				return fmt.Errorf("helper device update has no device")
			}
			h.replies.device.Store(&status)
		}
		call := entry.(*pipeCall)
		found, err := h.readFindings(call.texts)
		if _, ok := err.(requestError); err != nil && !ok {
			return err
		}
		call.reply <- pipeReply{found, err}
	}
}

func (h *helper) device() hello {
	if h.replies != nil {
		return *h.replies.device.Load()
	}
	return h.hello
}
