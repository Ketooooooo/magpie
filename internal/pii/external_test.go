package pii

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalModelProtocol(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAGPIE_TEST_EXTERNAL_DETECTOR", "1")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "privacy-models.json")
	spec := externalSpec{
		ID: "fixture", Name: "Fixture", Command: executable,
		Args: []string{"-test.run=^TestExternalModelFixture$"},
	}
	body, err := json.Marshal(map[string][]externalSpec{"externalPrivacyModels": {spec}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, body, 0o600); err != nil {
		t.Fatal(err)
	}
	models, err := loadExternalModels(cfg, dir)
	if err != nil || len(models) != 1 {
		t.Fatalf("models = %d, error = %v", len(models), err)
	}
	model := models[0]
	t.Cleanup(model.Stop)
	text := "测试 FixtureValue01"
	hits, err := model.Find(t.Context(), []string{text})
	if err != nil || len(hits) != 1 || len(hits[0]) != 1 {
		t.Fatalf("find = %+v, error = %v", hits, err)
	}
	h := hits[0][0]
	if h.Label != "secret" || h.Score != 0.75 || text[h.Start:h.End] != "FixtureValue01" {
		t.Fatalf("hit = %+v", h)
	}
	m := model.(*externalModel)
	first := m.helper
	if _, err := model.Find(t.Context(), []string{"another FixtureValue02"}); err != nil || m.helper != first {
		t.Fatalf("the helper was not reused: %v", err)
	}
	if _, err := model.Find(t.Context(), []string{"invalid FixtureValue03"}); err == nil || model.Now().Running {
		t.Fatalf("invalid spans did not fail detection and stop the helper: %v", err)
	}
}

func TestExternalModelFixture(t *testing.T) {
	if os.Getenv("MAGPIE_TEST_EXTERNAL_DETECTOR") != "1" {
		return
	}
	in, out := os.Stdin, os.Stdout
	io.WriteString(out, "{\"device\":\"CPU\"}\n")
	for {
		var count uint32
		if err := binary.Read(in, binary.LittleEndian, &count); err != nil {
			os.Exit(0)
		}
		binary.Write(out, binary.LittleEndian, uint32(0))
		for range count {
			var size uint32
			if err := binary.Read(in, binary.LittleEndian, &size); err != nil {
				os.Exit(1)
			}
			text := make([]byte, size)
			if _, err := io.ReadFull(in, text); err != nil {
				os.Exit(1)
			}
			at := strings.Index(string(text), "FixtureValue")
			if at < 0 {
				binary.Write(out, binary.LittleEndian, uint32(0))
				continue
			}
			end := uint32(len(text))
			if strings.HasPrefix(string(text), "invalid") {
				end++
			}
			for _, v := range []any{uint32(1), uint32(at), end, float32(.75), uint8(6)} {
				binary.Write(out, binary.LittleEndian, v)
			}
			io.WriteString(out, "secret")
		}
	}
}
