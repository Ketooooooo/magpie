package pii

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yetone/magpie/internal/pii/guard"
	"github.com/yetone/magpie/internal/proc"
	"github.com/yetone/magpie/internal/redact"
)

const AstrLinkServeCommand = "internal-astrlink-serve"

// startAstrLink runs the same executable so the worker has the build's Go
// inference code and, on macOS, the CoreML runtime bundled with it.
func startAstrLink(stop <-chan struct{}) (*helper, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	h, err := startHelper(proc.Command(exe, AstrLinkServeCommand, guardDir()), loadTimeout, "", stop)
	if err == nil {
		h.enableParallelPipe()
	}
	return h, err
}

type pipeCall struct {
	texts []string
	reply chan pipeReply
}

type pipeReply struct {
	found [][]redact.Found
	err   error
}

// AstrLink shares the helper handshake and span encoding. Request IDs let
// it return a short request before a long one on the same pipe.
type parallelPipe struct {
	next   atomic.Uint32
	calls  sync.Map // uint32 -> *pipeCall
	device atomic.Pointer[hello]
	done   chan struct{}
	err    error // published by closing done
}

func (h *helper) enableParallelPipe() {
	p := &parallelPipe{done: make(chan struct{})}
	p.device.Store(&h.hello)
	h.parallel = p
	go func() {
		p.err = h.readParallelReplies()
		close(p.done)
		h.kill()
	}()
}

func (h *helper) readParallelReplies() error {
	r := &reader{r: h.out}
	for {
		id := r.u32()
		if r.err != nil {
			return r.fail(h)
		}
		entry, ok := h.parallel.calls.Load(id)
		if !ok {
			return fmt.Errorf("unexpected AstrLink reply to request %d", id)
		}
		n := r.u32()
		if n > 64<<10 {
			return fmt.Errorf("invalid AstrLink device update length %d", n)
		}
		var status hello
		if err := json.Unmarshal(r.bytes(int(n)), &status); r.err != nil {
			return r.fail(h)
		} else if err != nil {
			return err
		}
		h.parallel.device.Store(&status)
		call := entry.(*pipeCall)
		found, err := h.readFindings(call.texts)
		if _, ok := err.(requestError); err != nil && !ok {
			return err
		}
		call.reply <- pipeReply{found, err}
	}
}

type spanFinder interface {
	Find(text string) []guard.Span
}

// ServeAstrLink is the internal worker command. Stdout is reserved for the
// helper protocol, and closing stdin ends the worker.
func ServeAstrLink(dir string, in io.Reader, out io.Writer) error {
	return serveAstrLink(in, out, func() (spanFinder, error) {
		m, err := guard.Load(dir)
		if err != nil {
			return nil, err
		}
		return m, nil
	})
}

func serveAstrLink(in io.Reader, out io.Writer, load func() (spanFinder, error)) error {
	start := time.Now()
	model, err := load()
	if err != nil {
		return json.NewEncoder(out).Encode(hello{Error: fmt.Sprintf("the local masking model didn't load: %v", err)})
	}
	loadMS := int(time.Since(start).Milliseconds())
	if err := json.NewEncoder(out).Encode(astrLinkDevice(model, loadMS)); err != nil {
		return err
	}
	r := &reader{r: bufio.NewReader(in)}
	slots := make(chan struct{}, guard.Cores())
	var write sync.Mutex
	var work sync.WaitGroup
	defer work.Wait()
	for {
		id := r.u32()
		if r.err == io.EOF {
			return nil
		}
		n := r.u32()
		if n > guardChunk {
			return fmt.Errorf("invalid AstrLink text count %d", n)
		}
		texts := make([]string, n)
		for i := range texts {
			size := r.u32()
			if size > guardChunk {
				return fmt.Errorf("invalid AstrLink text length %d", size)
			}
			texts[i] = string(r.bytes(int(size)))
		}
		if r.err != nil {
			return r.err
		}
		slots <- struct{}{}
		work.Go(func() {
			defer func() { <-slots }()
			found, err := classifySafely(func(texts []string) ([][]redact.Found, error) {
				out := make([][]redact.Found, len(texts))
				for i, t := range texts {
					for _, s := range model.Find(t) {
						out[i] = append(out[i], redact.Found{Start: s.Start, End: s.End, Label: guardLabel(s.Label), Score: s.Score})
					}
				}
				return out, nil
			}, texts)
			write.Lock()
			defer write.Unlock()
			var b bytes.Buffer
			put := func(v uint32) { binary.Write(&b, binary.LittleEndian, v) }
			status, _ := json.Marshal(astrLinkDevice(model, loadMS))
			put(id)
			put(uint32(len(status)))
			b.Write(status)
			if err != nil {
				put(1)
				put(uint32(len(err.Error())))
				b.WriteString(err.Error())
			} else {
				put(0)
				for _, spans := range found {
					put(uint32(len(spans)))
					for _, s := range spans {
						put(uint32(s.Start))
						put(uint32(s.End))
						put(math.Float32bits(float32(s.Score)))
						b.WriteByte(byte(len(s.Label)))
						b.WriteString(s.Label)
					}
				}
			}
			out.Write(b.Bytes())
		})
	}
}

func astrLinkDevice(m spanFinder, loadMS int) hello {
	s := hello{Device: "CPU", MS: loadMS}
	if b, ok := m.(interface {
		Backend() (via, device string, err error)
	}); ok {
		var err error
		s.Via, s.Device, err = b.Backend()
		if err != nil {
			s.GPUError = err.Error()
		}
	}
	return s
}
