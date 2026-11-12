package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yetone/magpie/internal/maskrec"
	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/privacyengine"
	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/settings"
)

func TestPrivacyEngineSwitchKeepsBothRecords(t *testing.T) {
	const value = "demo@gray-preview.internal"
	const token = "{{EMAIL_xxxxxxxx}}"
	const credential = "test-privacy-service-token-123456"
	const engineID = "test-detector"
	var offline atomic.Bool
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline.Load() || r.Header.Get("X-Test-Token") != credential {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/example/state":
			fmt.Fprint(w, `{"active_version":3}`)
		case "/example/scan":
			var in struct {
				Text    string `json:"text"`
				Version int    `json:"expected_version"`
			}
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Version != 3 {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			report := map[string]any{"complete": true, "protected_text": in.Text}
			if i := strings.Index(in.Text, value); i >= 0 {
				report["protected_text"] = strings.Replace(in.Text, value, token, 1)
				report["changes"] = []map[string]any{{"start": i, "end": i + len(value), "value": value, "placeholder": token, "category": "EMAIL", "reversible": true}}
			}
			_ = json.NewEncoder(w).Encode(report)
		default:
			http.NotFound(w, r)
		}
	}))
	defer service.Close()

	f := &fake{ctype: "application/json", reply: `{"id":"chatcmpl-1","object":"chat.completion","model":"m1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1}}`}
	setup(t, provider.Chat, f)
	ordinaryReply := f.reply
	oldDir := maskrec.Dir
	path := filepath.Join(t.TempDir(), "masking")
	maskrec.Dir = func() string { return path }
	t.Cleanup(func() { maskrec.Dir = oldDir })
	if got := privacyengine.Catalog(); len(got) != 1 || got[0].ID != privacyengine.Builtin {
		t.Fatalf("before installation, only Magpie should be listed: %+v", got)
	}
	dir := t.TempDir()
	manifest := []byte(`{"name":"test-detector","magpie":{"privacy":{"id":"test-detector","name":"Local detector","protocol":"http-scan-v1","statePath":"/example/state","scanPath":"/example/scan","tokenHeader":"X-Test-Token"}}}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.AddExact(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	if err := privacyengine.Select(t.Context(), engineID); err == nil {
		t.Fatal("selected an unconfigured engine")
	}
	if err := privacyengine.Configure(t.Context(), engineID, service.URL, credential); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(settings.Settings{RedactPersonal: true, RedactModelOff: true}); err != nil {
		t.Fatal(err)
	}
	body := `{"model":"fake/m1","messages":[{"role":"user","content":"contact ` + value + `"}]}`
	if code, _ := post(t, "/v1/chat/completions", body); code != 200 || strings.Contains(string(f.got), value) {
		t.Fatalf("built-in engine sent an unprotected request, or returned %d", code)
	}
	if err := privacyengine.Select(t.Context(), engineID); err != nil {
		t.Fatal(err)
	}
	f.reply = strings.Replace(f.reply, `"ok"`, `"`+token+`"`, 1)
	if code, reply := post(t, "/v1/chat/completions", body); code != 200 ||
		!strings.Contains(reply, value) || strings.Contains(string(f.got), value) || !strings.Contains(string(f.got), token) {
		t.Fatalf("Gray engine did not mask and restore: %d %s", code, reply)
	}
	records, _ := maskrec.List(0, 5, maskrec.Filter{})
	if len(records) < 2 || records[0].Engine != engineID || records[0].EngineName != "Local detector" || records[1].Engine != privacyengine.Builtin {
		t.Fatalf("expected consecutive Gray and Magpie records, got %+v", records)
	}
	f.ctype = "text/event-stream"
	f.reply = `data: {"id":"chatcmpl-2","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{"content":"{{EMAIL_xxx"}}]}

data: {"id":"chatcmpl-2","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{"content":"xxxxx}}"}}]}

data: {"id":"chatcmpl-2","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]

`
	stream := strings.Replace(body, `"model":`, `"stream":true,"model":`, 1)
	if code, reply := post(t, "/v1/chat/completions", stream); code != 200 || !strings.Contains(reply, value) || strings.Contains(reply, token) {
		t.Fatalf("Gray engine did not restore a split stream token: %d %s", code, reply)
	}
	offline.Store(true)
	f.got = nil
	if code, _ := post(t, "/v1/chat/completions", body); code != http.StatusServiceUnavailable || len(f.got) != 0 {
		t.Fatalf("offline Gray sent a provider request or returned %d", code)
	}
	if err := plugin.SetOff(dir, true); err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, "/v1/chat/completions", body); code != http.StatusServiceUnavailable || len(f.got) != 0 {
		t.Fatalf("a disabled selected engine sent a provider request or returned %d", code)
	}
	history, _ := maskrec.List(0, 5, maskrec.Filter{})
	if len(history) < 2 || history[0].EngineName != "Local detector" {
		t.Fatalf("disabling a plugin changed its history: %+v", history)
	}
	if err := privacyengine.Select(t.Context(), privacyengine.Disabled); err != nil {
		t.Fatal(err)
	}
	f.ctype, f.reply = "application/json", ordinaryReply
	if code, _ := post(t, "/v1/chat/completions", body); code != http.StatusOK || !strings.Contains(string(f.got), value) {
		t.Fatalf("None should send an ordinary request as written, got %d", code)
	}
	if settings.Shared().PrivacyEngine != privacyengine.Disabled {
		t.Fatal("None was not persisted")
	}
	afterNone, _ := maskrec.List(0, 5, maskrec.Filter{})
	if len(afterNone) != len(history) || afterNone[0].Key != history[0].Key {
		t.Fatal("selecting None changed the masking history")
	}
	if err := privacyengine.Select(t.Context(), privacyengine.Builtin); err != nil {
		t.Fatal(err)
	}
	if !settings.Shared().RedactPersonal {
		t.Fatal("switching back lost the Magpie policy")
	}
	if code, _ := post(t, "/v1/chat/completions", body); code != http.StatusOK || strings.Contains(string(f.got), value) {
		t.Fatalf("returning to Magpie did not resume masking, got %d", code)
	}
}
