package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/maskrec"
	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/privacyengine"
	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/settings"
	"github.com/yetone/magpie/internal/testenv"
)

func TestPrivacyEngineSwitchKeepsBothRecords(t *testing.T) {
	t.Setenv("MAGPIE_BUN", testenv.Bun(t))
	t.Cleanup(plugin.Settle)
	const value = "demo@gray-preview.internal"
	const token = "{{EMAIL_xxxxxxxx}}"
	const engineID = "test-detector"
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
	manifest := `{"name":"test-detector","magpie":{"privacy":{"id":"test-detector","name":"Local detector","protocol":"plugin-scan-v1","entry":"privacy.mjs"}}}`
	code := `
import { existsSync } from "node:fs";
export function protect(fragments) {
  if (existsSync(new URL("./offline", import.meta.url))) throw new Error("detector unavailable");
  return { version: 1, reports: fragments.map(({text}) => {
    const value = "` + value + `", token = "` + token + `";
    const index = text.indexOf(value);
    const start = Buffer.byteLength(text.slice(0, index));
    const changes = index >= 0 ? [{start, end: start + value.length, value, placeholder: token, category: "EMAIL", reversible: true}] : [];
    return {complete: true, protected_text: text.replace(value, token), changes};
  }) };
}
`
	for name, contents := range map[string]string{"package.json": manifest, "privacy.mjs": code} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := plugin.AddExact(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(settings.Settings{RedactPersonal: true, RedactModelOff: true}); err != nil {
		t.Fatal(err)
	}
	body := `{"model":"fake/m1","messages":[{"role":"user","content":"联络 ` + value + `"}]}`
	if code, _ := post(t, "/v1/chat/completions", body); code != 200 || strings.Contains(string(f.got), value) {
		t.Fatalf("built-in engine sent an unprotected request, or returned %d", code)
	}
	if err := privacyengine.Select(t.Context(), engineID); err != nil {
		t.Fatal(err)
	}
	f.reply = strings.Replace(f.reply, `"ok"`, `"`+token+`"`, 1)
	s := New()
	reply := httptest.NewRecorder()
	s.Handler().ServeHTTP(reply, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	if reply.Code != http.StatusOK || !strings.Contains(reply.Body.String(), value) ||
		strings.Contains(string(f.got), value) || !strings.Contains(string(f.got), token) {
		t.Fatalf("hosted engine did not mask and restore: %d %s", reply.Code, reply.Body)
	}
	routes := s.Trace(context.Background(), 0, 0).Routes
	if len(routes) != 1 {
		t.Fatalf("expected one route, got %d", len(routes))
	}
	prompt, ok := s.PromptText(routes[0].ID, PartChat, true)
	raw, _ := json.Marshal(prompt)
	if !ok || strings.Contains(string(raw), value) || !strings.Contains(string(raw), token) {
		t.Fatalf("prompt inspection should contain only the protected request: %s", raw)
	}
	if _, _, _, ok := s.ReplyBody(routes[0].ID); ok {
		t.Fatal("the reply body should not be retained for a plugin-protected request")
	}
	upstream, err := provider.Find("fake")
	if err != nil {
		t.Fatal(err)
	}
	upstream.Unredacted = true
	if err := provider.Save(*upstream); err != nil {
		t.Fatal(err)
	}
	plainServer := New()
	plainReply := httptest.NewRecorder()
	plainServer.Handler().ServeHTTP(plainReply, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	plainRoutes := plainServer.Trace(context.Background(), 0, 0).Routes
	if plainReply.Code != http.StatusOK || !strings.Contains(string(f.got), value) || len(plainRoutes) != 1 {
		t.Fatal("expected a request sent as written to the opted-out provider")
	}
	if _, ok := plainServer.PromptText(plainRoutes[0].ID, PartChat, true); ok {
		t.Fatal("prompt inspection must omit the opted-out provider's request")
	}
	upstream.Unredacted = false
	if err := provider.Save(*upstream); err != nil {
		t.Fatal(err)
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
	if err := os.WriteFile(filepath.Join(dir, "offline"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
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
	if err := plugin.SetOff(dir, false); err != nil {
		t.Fatal(err)
	}
	if err := privacyengine.Select(t.Context(), engineID); err == nil || privacyengine.ID(settings.Shared()) != privacyengine.Builtin {
		t.Fatal("selecting an unavailable plugin should leave Magpie selected")
	}
}
