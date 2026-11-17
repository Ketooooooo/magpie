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
	return startHelper(proc.Command(exe, AstrLinkServeCommand, guardDir()), loadTimeout, "", stop)
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
	lastDevice := astrLinkDevice(model, loadMS)
	ready := lastDevice
	ready.Protocol = helperProtocol
	if err := json.NewEncoder(out).Encode(ready); err != nil {
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
			var status []byte
			if device := astrLinkDevice(model, loadMS); device != lastDevice {
				status, _ = json.Marshal(device)
				lastDevice = device
			}
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
