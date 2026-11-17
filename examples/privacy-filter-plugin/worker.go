package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/proc"
)

const protocol = 2

type ready struct {
	Protocol int    `json:"protocol,omitempty"`
	GPUAgain int64  `json:"gpuAgain,omitempty"`
	GPUReset bool   `json:"gpuReset,omitempty"`
	Device   string `json:"device,omitempty"`
	GPU      bool   `json:"gpu,omitempty"`
	MS       int    `json:"ms,omitempty"`
	GPUError string `json:"gpuError,omitempty"`
	Error    string `json:"error,omitempty"`
}

type candidate struct {
	path string
	cpu  bool
}

func candidates(cpu bool) []candidate {
	if !fullX86() {
		if base := exe("pf-serve-base"); available(base) {
			return []candidate{{base, true}}
		}
	}
	main := exe("pf-serve")
	var out []candidate
	if !cpu && os.Getenv("PF_DEVICE") != "cpu" {
		if vulkan := exe("pf-serve-vulkan"); available(vulkan) {
			out = append(out, candidate{vulkan, false})
		} else if runtime.GOOS == "darwin" {
			out = append(out, candidate{main, false})
		}
	}
	return append(out, candidate{main, true})
}

func available(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

type worker struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	state  ready
	stderr *diagnostics
}

func start(ctx context.Context, weights string, c candidate) (*worker, error) {
	// The native worker reads the file in its working directory, so an
	// ASCII-named weight file can be in a non-ASCII Windows user directory.
	// ctx limits the startup wait. A worker that became ready can serve
	// later requests after this context ends.
	cmd := proc.Command(c.path, filepath.Base(weights))
	cmd.Dir = filepath.Dir(weights)
	cmd.Env = append(cmd.Environ(), "GGML_METAL_NO_RESIDENCY=1", "MAGPIE_PII_PROTOCOL=0")
	if c.cpu {
		cmd.Env = append(cmd.Env, "PF_DEVICE=cpu")
	}
	stderr := &diagnostics{}
	cmd.Stderr = stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	w := &worker{cmd: cmd, in: in, out: bufio.NewReader(out), stderr: stderr}
	wait := 40 * time.Second
	if c.cpu {
		wait = 2 * time.Minute
	}
	s, err := timed(ctx, wait, func() (ready, error) {
		line, err := w.out.ReadString('\n')
		var s ready
		if err == nil {
			err = json.Unmarshal([]byte(line), &s)
		}
		if err == nil && (s.Error != "" || s.Device == "") {
			err = fmt.Errorf("no model ready: %s", s.Error)
		}
		return s, err
	}, w.kill)
	if err != nil {
		w.close()
		return nil, fmt.Errorf("%s: %w", filepath.Base(c.path), err)
	}
	w.state = s
	return w, nil
}

func (w *worker) kill() { _ = w.cmd.Process.Kill() }

func (w *worker) close() {
	w.in.Close()
	w.kill()
	_ = w.cmd.Wait()
}

func timed[T any](ctx context.Context, timeout time.Duration, f func() (T, error), kill func()) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		kill()
	})
	out, err := f()
	if !stop() {
		<-done
		return out, ctx.Err()
	}
	return out, err
}

func openWorker(ctx context.Context, weights string, cpu bool) (*worker, error) {
	var failures []error
	for _, c := range candidates(cpu) {
		w, err := start(ctx, weights, c)
		if err == nil {
			if len(failures) > 0 && w.state.GPUError == "" {
				w.state.GPUError = errors.Join(failures...).Error()
			}
			return w, nil
		}
		failures = append(failures, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(failures...)
}

// session keeps device policy private to this plugin. Magpie sees one
// serial detector, regardless of which engine answers a request.
type session struct {
	worker  *worker
	weights string
	// A device that repeatedly fails is retried after a cooldown.
	gpuFailures int
	gpuAgain    time.Time
	gpuError    string
}

func (s *session) open(ctx context.Context, cpu bool) error {
	w, err := openWorker(ctx, s.weights, cpu)
	if err != nil {
		return err
	}
	s.worker = w
	if !cpu && !w.state.GPU && w.state.GPUError != "" {
		s.loseGPU(w.state.GPUError)
	}
	return nil
}

func (s *session) loseGPU(reason string) {
	s.gpuError = reason
	s.gpuFailures++
	backoff := 10 * time.Minute
	for i := 1; i < s.gpuFailures && backoff < 2*time.Hour; i++ {
		backoff *= 2
	}
	s.gpuAgain = time.Now().Add(min(backoff, 2*time.Hour))
}

func (s *session) close() {
	if s.worker != nil {
		s.worker.close()
		s.worker = nil
	}
}

// Leave time to return before the host's five-minute watchdog, even if
// recovery spans several native starts and inference attempts.
const requestBudget = 4*time.Minute + 55*time.Second

func (s *session) classify(ctx context.Context, frame []byte, sizes []int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestBudget)
	defer cancel()
	if !s.gpuAgain.IsZero() && !time.Now().Before(s.gpuAgain) {
		s.close()
		s.gpuAgain = time.Time{}
		if err := s.open(ctx, false); err != nil {
			return nil, err
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		reply, err := s.worker.classify(ctx, frame, sizes)
		if err == nil {
			if s.worker.state.GPU {
				s.gpuFailures, s.gpuError, s.gpuAgain = 0, "", time.Time{}
			}
			return reply, nil
		}
		if !s.worker.state.GPU || attempt == 2 || ctx.Err() != nil {
			return nil, err
		}
		w := s.worker
		s.close()
		if attempt == 1 {
			reason := err.Error()
			if w.stderr.deviceLost() {
				reason = "device lost"
			}
			s.loseGPU(reason)
		}
		if err := s.open(ctx, attempt == 1); err != nil {
			return nil, err
		}
	}
	panic("unreachable")
}

func (s *session) device() ready {
	d := s.worker.state
	if !s.gpuAgain.IsZero() {
		d.GPUAgain = s.gpuAgain.UnixMilli()
		d.GPUError = s.gpuError
	}
	d.GPUReset = d.GPUError == "device lost"
	return d
}

func serve(ctx context.Context, weights string, in io.Reader, out io.Writer) error {
	weights, err := filepath.Abs(weights)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	s := session{weights: weights}
	if err := s.open(ctx, false); err != nil {
		return enc.Encode(ready{Error: err.Error()})
	}
	defer s.close()
	framed := os.Getenv("MAGPIE_PII_PROTOCOL") == "2"
	last := s.device()
	hello := last
	if framed {
		hello.Protocol = protocol
	}
	if err := enc.Encode(hello); err != nil {
		return err
	}
	for {
		var id uint32
		if framed {
			if err := binary.Read(in, binary.LittleEndian, &id); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
		frame, sizes, err := readRequest(in)
		if err == io.EOF && !framed {
			return nil
		}
		if err != nil {
			return err
		}
		reply, err := s.classify(ctx, frame, sizes)
		if err != nil {
			return err
		}
		if framed {
			var update []byte
			if current := s.device(); current != last {
				update, err = json.Marshal(current)
				if err != nil {
					return err
				}
				last = current
			}
			if err := binary.Write(out, binary.LittleEndian, [2]uint32{id, uint32(len(update))}); err != nil {
				return err
			}
			if _, err := out.Write(update); err != nil {
				return err
			}
		}
		if _, err := out.Write(reply); err != nil {
			return err
		}
	}
}

const maxFrame = 1 << 20

func readRequest(in io.Reader) ([]byte, []int, error) {
	var frame bytes.Buffer
	r := wireReader{in: io.TeeReader(in, &frame)}
	n := r.u32()
	if r.err != nil {
		return nil, nil, r.err
	}
	if n > maxFrame/4 {
		return nil, nil, errors.New("too many detection inputs")
	}
	sizes := make([]int, n)
	for i := range sizes {
		size := r.u32()
		if size > maxFrame || frame.Len()+int(size) > maxFrame {
			return nil, nil, errors.New("detection input is too large")
		}
		sizes[i] = int(size)
		r.copy(int64(size))
	}
	if r.err == io.EOF {
		r.err = io.ErrUnexpectedEOF
	}
	return frame.Bytes(), sizes, r.err
}

func (w *worker) classify(ctx context.Context, frame []byte, sizes []int) ([]byte, error) {
	wait := 30*time.Second + time.Duration(len(frame)/4096)*time.Second
	return timed(ctx, wait, func() ([]byte, error) {
		if _, err := w.in.Write(frame); err != nil {
			return nil, err
		}
		var reply bytes.Buffer
		r := wireReader{in: io.TeeReader(w.out, &reply)}
		switch r.u32() {
		case 0:
			for _, size := range sizes {
				n := r.u32()
				if n > uint32(size)+1 {
					return nil, fmt.Errorf("invalid detector reply: %d spans for %d bytes", n, size)
				}
				for i := uint32(0); i < n && r.err == nil; i++ {
					r.copy(12)
					var length [1]byte
					r.read(length[:])
					r.copy(int64(length[0]))
				}
			}
		case 1:
			n := r.u32()
			if n > maxFrame {
				return nil, errors.New("detector error reply is too large")
			}
			r.copy(int64(n))
		default:
			return nil, errors.New("invalid detector reply status")
		}
		if r.err != nil {
			return nil, r.err
		}
		return reply.Bytes(), nil
	}, w.kill)
}

type wireReader struct {
	in  io.Reader
	err error
}

func (r *wireReader) read(b []byte) {
	if r.err == nil {
		_, r.err = io.ReadFull(r.in, b)
	}
}

func (r *wireReader) u32() uint32 {
	var b [4]byte
	r.read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func (r *wireReader) copy(n int64) {
	if r.err == nil {
		_, r.err = io.CopyN(io.Discard, r.in, n)
	}
}

// diagnostics only exposes the known device-lost condition, never raw
// inference diagnostics from a child process.
type diagnostics struct {
	mu   sync.Mutex
	tail string
}

func (d *diagnostics) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tail += string(p)
	if len(d.tail) > 4096 {
		d.tail = d.tail[len(d.tail)-4096:]
	}
	return len(p), nil
}
func (d *diagnostics) deviceLost() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := strings.ToLower(d.tail)
	return strings.Contains(s, "device lost") || strings.Contains(s, "devicelost")
}
