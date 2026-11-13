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

	"github.com/tidwall/gjson"

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
	const token = "[[private-email-1]]"
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
	manifest := `{"name":"test-detector","magpie":{"privacy":{"id":"test-detector","name":"Local detector","protocol":"body-v1","entry":"privacy.mjs"}}}`
	code := `
import { existsSync } from "node:fs";
const value = "` + value + `", token = "` + token + `";
export function preview({body, texts}) {
  if (existsSync(new URL("./offline", import.meta.url))) throw new Error("detector unavailable");
  const hits = [];
  const mask = text => {
    if (text.includes(value)) hits.push({kind: "EMAIL", placeholder: token});
    return text.replaceAll(value, token);
  };
  const result = body ? {body: mask(body)} : {texts: texts.map(mask)};
  return {...result, hits, restore: hits.length > 0};
}
export function begin(input) {
  const request = preview(input);
  const notice = '\n\n🔒 Magpie masked the following values before sending them to the model.\n\n- [' +
    value + '](#magpie-privacy-notice "' + token + '")';
  const structured = Boolean(input.body && JSON.parse(input.body).response_format);
  let buffer = "", tail = "", restored = false;
  const result = data => ({data: Buffer.from(data).toString("base64"), put: restored ? {[token]:1} : {}});
  return {request: () => request, reply: ({data, contentType, present, finish}) => {
    if (data) buffer += Buffer.from(data, "base64").toString();
    if (contentType.includes("event-stream")) {
      let out = "", at;
      while ((at = buffer.indexOf("\n\n")) >= 0) {
        const frame = buffer.slice(0, at);
        buffer = buffer.slice(at + 2);
        if (!frame.startsWith("data: {")) { out += frame + "\n\n"; continue; }
        const event = JSON.parse(frame.slice(6)), choice = event.choices?.[0];
        if (choice) {
          const delta = choice.delta ??= {};
          const text = tail + (delta.content ?? "");
          const split = !choice.finish_reason && text.endsWith("[[private-");
          tail = split ? "[[private-" : "";
          if (text.includes(token)) restored = true;
          if (text) delta.content = text.slice(0, text.length - tail.length).replaceAll(token, value);
          if (restored && present && !structured && choice.finish_reason === "stop") delta.content = (delta.content ?? "") + notice;
        }
        out += "data: " + JSON.stringify(event) + "\n\n";
      }
      return result(out);
    }
    if (!finish || !buffer) return {};
    restored = buffer.includes(token);
    const event = JSON.parse(buffer.replaceAll(token, value));
    if (restored && present && !structured && event.choices?.[0]?.finish_reason === "stop") event.choices[0].message.content += notice;
    return result(JSON.stringify(event));
  }};
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
	content := gjson.Get(reply.Body.String(), "choices.0.message.content").String()
	notice := "\n\n🔒 Magpie masked the following values before sending them to the model.\n\n- [" + value + `](#magpie-privacy-notice "` + token + `")`
	if content != value+notice {
		t.Fatalf("reply should restore the body and add the plugin notice, got %q", content)
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
	structured := strings.Replace(body, `{"model":`, `{"response_format":{"type":"json_object"},"model":`, 1)
	if code, reply := post(t, "/v1/chat/completions", structured); code != http.StatusOK ||
		gjson.Get(reply, "choices.0.message.content").String() != value {
		t.Fatalf("structured requests must skip the reply notice, got %d %s", code, reply)
	}
	internalReply := httptest.NewRecorder()
	internalReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	New().serve(internalReply, internalReq.WithContext(ownAsk(internalReq.Context())), provider.Chat, []byte(body))
	if internalReply.Code != http.StatusOK || gjson.Get(internalReply.Body.String(), "choices.0.message.content").String() != value {
		t.Fatalf("internal requests must skip the reply notice, got %d %s", internalReply.Code, internalReply.Body.String())
	}
	f.ctype = "text/event-stream"
	f.reply = `data: {"id":"chatcmpl-2","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{"content":"[[private-"}}]}

data: {"id":"chatcmpl-2","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{"content":"email-1]]"}}]}

data: {"id":"chatcmpl-2","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]

`
	stream := strings.Replace(body, `"model":`, `"stream":true,"model":`, 1)
	if code, reply := post(t, "/v1/chat/completions", stream); code != 200 ||
		strings.Count(reply, token) != 1 || strings.Count(reply, value) != 2 ||
		!strings.Contains(reply, "#magpie-privacy-notice") || strings.Index(reply, "#magpie-privacy-notice") > strings.Index(reply, "[DONE]") {
		t.Fatalf("Gray engine did not restore a split stream token and add its notice: %d %s", code, reply)
	}
	f.ctype = "application/json"
	f.reply = ordinaryReply
	for _, original := range []string{value, "plain"} {
		history := map[string]any{"model": "fake/m1", "messages": []map[string]string{
			{"role": "assistant", "content": original + notice},
			{"role": "user", "content": "Continue"},
		}}
		raw, _ := json.Marshal(history)
		if code, _ := post(t, "/v1/chat/completions", string(raw)); code != 200 {
			t.Fatalf("assistant history failed: %d", code)
		}
		if strings.Contains(string(f.got), "#magpie-privacy-notice") || strings.Contains(string(f.got), value) ||
			!strings.Contains(string(f.got), strings.ReplaceAll(original, value, token)) {
			t.Fatalf("assistant history did not lose its notice and retain its protected body: %s", f.got)
		}
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

func TestPrivacyNoticeRemovedBeforeEngineSelection(t *testing.T) {
	const current = "\n\n🔒 Magpie masked the following values before sending them to the model.\n\n" +
		`- [example](#magpie-privacy-notice "{{EMAIL_abcdefgh}}")`
	const preview = "\n\n🔒 Gray masked the following values before sending them to the model.\n\n" +
		`- [example](#magpie-privacy-notice "{{EMAIL_abcdefgh}}")`
	for _, engine := range []string{privacyengine.Builtin, privacyengine.Disabled} {
		t.Run(engine, func(t *testing.T) {
			f := &fake{ctype: "application/json", reply: `{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`}
			setup(t, provider.Chat, f)
			if err := settings.Save(settings.Settings{PrivacyEngine: engine, RedactPersonal: true, RedactModelOff: true}); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]any{"model": "fake/m1", "messages": []map[string]string{
				{"role": "assistant", "content": "First reply." + current},
				{"role": "assistant", "content": "Second reply." + preview},
				{"role": "user", "content": "Continue." + current},
			}})
			if code, _ := post(t, "/v1/chat/completions", string(body)); code != http.StatusOK {
				t.Fatalf("request returned %d", code)
			}
			messages := gjson.GetBytes(f.got, "messages").Array()
			if len(messages) != 3 || messages[0].Get("content").String() != "First reply." ||
				messages[1].Get("content").String() != "Second reply." ||
				messages[2].Get("content").String() != "Continue."+current {
				t.Fatalf("notice cleanup should apply only to assistant history, got %s", f.got)
			}
		})
	}
}
