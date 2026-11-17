package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/testenv"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("PF_TEST_WORKER"); mode != "" {
		os.Exit(fakeWorker(mode))
	}
	testenv.Main(m)
}

func fakeWorker(mode string) int {
	gpu := os.Getenv("PF_DEVICE") != "cpu"
	device := "CPU"
	if gpu {
		device = "GPU"
	}
	if _, err := os.Stat(os.Args[1]); err != nil || filepath.IsAbs(os.Args[1]) {
		return 2
	}
	if mode == "missing-vulkan" && gpu {
		return 3
	}
	if err := json.NewEncoder(os.Stdout).Encode(ready{Device: device, GPU: gpu}); err != nil {
		return 4
	}
	for {
		_, sizes, err := readRequest(os.Stdin)
		if err == io.EOF {
			return 0
		}
		if err != nil {
			return 5
		}
		if gpu && mode == "device-lost" {
			fmt.Fprintln(os.Stderr, "vk::DeviceLostError")
			return 6
		}
		if err := binary.Write(os.Stdout, binary.LittleEndian, make([]uint32, len(sizes)+1)); err != nil {
			return 7
		}
	}
}

func fakeAssets(t *testing.T, mode string) string {
	t.Helper()
	was := dir
	// The worker reads the model from its own working directory.
	root := filepath.Join(t.TempDir(), "用户")
	dir = func() string { return root }
	t.Cleanup(func() { dir = was })
	t.Setenv("PF_TEST_WORKER", mode)
	t.Setenv("PF_DEVICE", "")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(serveDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pf-serve", "pf-serve-vulkan"} {
		if err := os.WriteFile(exeIn(serveDir(), name), payload, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := modelPath()
	if err := os.WriteFile(path, []byte("fake GGUF"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMissingVulkanFallsBackAtStartup(t *testing.T) {
	path := fakeAssets(t, "missing-vulkan")
	s := session{weights: path}
	defer s.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.open(ctx, false); err != nil {
		t.Fatal(err)
	}
	if d := s.device(); d.Device != "CPU" || d.GPU || d.GPUError == "" || d.GPUAgain == 0 {
		t.Fatalf("device after startup failure: %+v", d)
	}
}

func TestDeviceLossRetriesAndReportsChangeOnce(t *testing.T) {
	path := fakeAssets(t, "device-lost")
	t.Setenv("MAGPIE_PII_PROTOCOL", "2")
	var in, out bytes.Buffer
	for _, id := range []uint32{42, 43} {
		binary.Write(&in, binary.LittleEndian, [3]uint32{id, 1, 5})
		in.WriteString("Alice")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := serve(ctx, path, &in, &out); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(&out)
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var initial ready
	if err := json.Unmarshal(line, &initial); err != nil || initial.Protocol != 2 || !initial.GPU {
		t.Fatalf("initial ready: %s, %v", line, err)
	}
	f := wireReader{in: r}
	id, length := f.u32(), f.u32()
	if id != 42 || length == 0 || length > 64<<10 {
		t.Fatalf("first reply ID %d, device update bytes %d", id, length)
	}
	data := make([]byte, length)
	f.read(data)
	var changed ready
	if err := json.Unmarshal(data, &changed); err != nil || changed.Device != "CPU" || changed.GPU || !changed.GPUReset || changed.GPUAgain == 0 {
		t.Fatalf("device after request: %s, %v", data, err)
	}
	if f.u32() != 0 || f.u32() != 0 {
		t.Fatal("first response did not complete with the CPU result")
	}
	if f.u32() != 43 || f.u32() != 0 || f.u32() != 0 || f.u32() != 0 || f.err != nil {
		t.Fatalf("second response sent a device update or was incomplete: %v", f.err)
	}
}

func TestLegacyRequestWithoutProtocol(t *testing.T) {
	path := fakeAssets(t, "ok")
	t.Setenv("MAGPIE_PII_PROTOCOL", "")
	t.Setenv("PF_DEVICE", "cpu")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	in := strings.NewReader("\x01\x00\x00\x00\x05\x00\x00\x00Alice")
	var out bytes.Buffer
	if err := serve(ctx, path, in, &out); err != nil {
		t.Fatal(err)
	}
	line, err := out.ReadString('\n')
	if err != nil || strings.Contains(line, "protocol") || !bytes.Equal(out.Bytes(), make([]byte, 8)) {
		t.Fatalf("legacy handshake or reply: %q %x (%v)", line, out.Bytes(), err)
	}
}
