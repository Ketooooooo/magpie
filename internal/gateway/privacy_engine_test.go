package gateway

import (
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

const (
	testPrivacyEngine = "test-detector"
	testPrivateValue  = "demo@privacy-engine.internal"
	testPlaceholder   = "[[private-email-1]]"
)

func installPrivacyEngine(t *testing.T) string {
	t.Helper()
	t.Setenv("MAGPIE_BUN", testenv.Bun(t))
	t.Cleanup(plugin.Settle)
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"package.json": `{"name":"test-detector","magpie":{"privacy":{"id":"test-detector","name":"Local detector","protocol":"body-v1","entry":"privacy.mjs"}}}`,
		"privacy.mjs": `
const value = "` + testPrivateValue + `", token = "` + testPlaceholder + `";
export function preview({body, texts}) {
  const hits = [];
  const mask = text => {
    if (text.includes(value)) hits.push({kind:"EMAIL", placeholder:token});
    return text.replaceAll(value, token);
  };
  return {...(body ? {body:mask(body)} : {texts:texts.map(mask)}), hits, restore:hits.length > 0};
}
export function begin(input) {
  const request = preview(input);
  let buffer = "";
  return {request: () => request, reply: ({data, contentType, finish}) => {
    if (data) buffer += Buffer.from(data, "base64").toString();
    const boundary = contentType.includes("event-stream") ? buffer.lastIndexOf("\n\n") : -1;
    const end = finish ? buffer.length : boundary < 0 ? 0 : boundary + 2;
    if (!end) return {};
    const ready = buffer.slice(0, end);
    buffer = buffer.slice(end);
    const put = ready.includes(token) ? {[token]:1} : {};
    return {data:Buffer.from(ready.replaceAll(token, value)).toString("base64"), put};
  }};
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := plugin.AddExact(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPrivacyEngineSwitchKeepsBothRecords(t *testing.T) {
	f := &fake{ctype: "application/json", reply: `{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`}
	setup(t, provider.Chat, f)
	dir := installPrivacyEngine(t)
	if err := settings.Save(settings.Settings{RedactPersonal: true, RedactModelOff: true}); err != nil {
		t.Fatal(err)
	}
	selectEngine := func(id string) {
		t.Helper()
		if err := privacyengine.Select(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	const path = "/v1/chat/completions"
	body := `{"model":"fake/m1","messages":[{"role":"user","content":"` + testPrivateValue + `"}]}`
	if code, _ := post(t, path, body); code != 200 || strings.Contains(string(f.got), testPrivateValue) {
		t.Fatalf("the default engine did not protect the request: status %d", code)
	}

	selectEngine(testPrivacyEngine)
	f.ctype = "text/event-stream"
	f.reply = sse(
		`data: {"id":"chat-1","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{"content":"`+testPlaceholder+`"}}]}`,
		`data: {"id":"chat-1","object":"chat.completion.chunk","model":"m1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		"data: [DONE]",
	)
	stream := strings.Replace(body, `{"model":`, `{"stream":true,"model":`, 1)
	if code, reply := post(t, path, stream); code != 200 ||
		!strings.Contains(string(f.got), testPlaceholder) || strings.Contains(string(f.got), testPrivateValue) ||
		!strings.Contains(reply, testPrivateValue) || strings.Contains(reply, testPlaceholder) {
		t.Fatalf("the hosted engine did not mask and restore streamed text: status %d", code)
	}
	records, _ := maskrec.List(0, 2, maskrec.Filter{})
	if len(records) != 2 || records[0].Engine != testPrivacyEngine || records[0].Back[testPlaceholder] != 1 ||
		records[1].Engine != privacyengine.Builtin {
		t.Fatalf("expected masking records for both engines and the hosted restoration: %+v", records)
	}

	if err := plugin.SetOff(dir, true); err != nil {
		t.Fatal(err)
	}
	f.got = nil
	if code, _ := post(t, path, body); code != http.StatusServiceUnavailable || len(f.got) != 0 {
		t.Fatalf("the unavailable selected engine did not hold the request: status %d", code)
	}
	selectEngine(privacyengine.Disabled)
	f.ctype = "application/json"
	f.reply = `{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`
	if code, _ := post(t, path, body); code != 200 || !strings.Contains(string(f.got), testPrivateValue) {
		t.Fatalf("None did not send the request as written: status %d", code)
	}
}

func TestHostedPrivacyArchiveKeepsOnlyProtectedRequest(t *testing.T) {
	f := &fake{ctype: "application/json", reply: `{"choices":[{"index":0,"message":{"role":"assistant","content":"` + testPlaceholder + `"},"finish_reason":"stop"}]}`}
	setup(t, provider.Chat, f)
	installPrivacyEngine(t)
	bucket := &memBucket{objs: map[string][]byte{}}
	archiveTo(t, bucket)
	if err := settings.Save(settings.Settings{RequestArchive: true}); err != nil {
		t.Fatal(err)
	}
	if err := privacyengine.Select(t.Context(), testPrivacyEngine); err != nil {
		t.Fatal(err)
	}
	body := `{"model":"fake/m1","messages":[{"role":"user","content":"` + testPrivateValue + `"}]}`
	rec := httptest.NewRecorder()
	New().Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	archivePending.Wait()
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), testPrivateValue) {
		t.Fatalf("the client did not get the restored reply: status %d", rec.Code)
	}
	archives := archivedOf(t, bucket)["fake"]
	if len(archives) != 1 {
		t.Fatalf("expected one archived request, got %d", len(archives))
	}
	a := archives[0]
	if strings.Contains(a.Request.Body, testPrivateValue) || !strings.Contains(a.Request.Body, testPlaceholder) || a.Response.Body != "" {
		t.Fatal("archive must keep the protected request and omit the restored reply")
	}
}
