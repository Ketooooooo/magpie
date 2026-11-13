package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/privacyengine"
	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/sessions"
	"github.com/yetone/magpie/internal/settings"
	"github.com/yetone/magpie/internal/testenv"
	"github.com/yetone/magpie/internal/usage"
)

func TestHostedPrivacyRequestBatchAndCapture(t *testing.T) {
	t.Setenv("MAGPIE_BUN", testenv.Bun(t))
	const first, second = "data:private-one", "private-two"
	const firstMask, secondMask = "{{FIELD_aaaaaaaa}}", "{{FIELD_bbbbbbbb}}"
	f := &fake{ctype: "application/json", reply: `{"fields":["` + firstMask + `","` + secondMask + `"]}`}
	up := setup(t, provider.Chat, f)
	if err := provider.Save(provider.Provider{ID: "near", Name: "Nearby", Key: "local", Chat: up.URL + "/v1", Models: []string{"m1"}, Unredacted: true}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Cleanup(plugin.Settle)
	t.Cleanup(archivePending.Wait)
	files := map[string]string{
		"package.json": `{"name":"batch-privacy","magpie":{"privacy":{"id":"batch-privacy","name":"Batch privacy","protocol":"plugin-scan-v1","entry":"privacy.mjs"}}}`,
		"privacy.mjs": `
import { appendFileSync } from "node:fs";
const values = new Map([["` + first + `","` + firstMask + `"], ["` + second + `","` + secondMask + `"]]);
export function protect(fragments, {preview}) {
  if (!preview) appendFileSync(new URL("./batches", import.meta.url), fragments.length + "\n");
  return {reports: fragments.map(({text}) => {
    const mask = values.get(text);
    const changes = mask ? [{start: 0, end: text.length, value: text, placeholder: mask, category: "FIELD", reversible: true}] : [];
    return {complete: true, protected_text: mask ?? text, changes};
  })};
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := plugin.AddExact(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	// Inactive Magpie settings must not alter hosted protection or its route.
	if err := settings.Save(settings.Settings{RedactAllow: []string{first}, RedactRouteTo: "near/m1", RequestArchiveLocal: true}); err != nil {
		t.Fatal(err)
	}
	if err := privacyengine.Select(t.Context(), "batch-privacy"); err != nil {
		t.Fatal(err)
	}
	if err := sessions.SetGatewayRecording(true, false); err != nil {
		t.Fatal(err)
	}
	s := New()
	native := httptest.NewRecorder()
	r := httptest.NewRequest("POST", NativePath+"fake/v1/test", strings.NewReader(
		`{"input":"`+first+`","extras":{"id":"`+second+`"}}`))
	r.RemoteAddr = "127.0.0.1:50000"
	s.Handler().ServeHTTP(native, r)
	if native.Code != http.StatusOK || native.Body.String() != `{"fields":["`+first+`","`+second+`"]}` ||
		!strings.Contains(string(f.got), firstMask) || !strings.Contains(string(f.got), secondMask) {
		t.Fatalf("native request and reply must share restoration: %d %s, sent %s", native.Code, native.Body, f.got)
	}
	unknown, _ := post(t, "/v1/chat/completions", `{"model":"nobody/missing","messages":[{"role":"user","content":"`+second+`"}]}`)
	if batches, err := os.ReadFile(filepath.Join(dir, "batches")); unknown != http.StatusNotFound || string(batches) != "2\n" || err != nil {
		t.Fatalf("native should scan both strings once and a rejected request should not scan: status %d, batches %q, %v", unknown, batches, err)
	}

	f.reply = `{"choices":[{"index":0,"message":{"role":"assistant","content":"` + secondMask + `"},"finish_reason":"stop"}]}`
	check := func(id string, status int, unmasked bool) {
		t.Helper()
		o := &fakeObserver{watch: true, bodies: usage.WholeBodies}
		defer usage.Observe(o)()
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(
			`{"model":"fake/m1","messages":[{"role":"user","content":"`+second+`"}]}`))
		r.Header.Set("User-Agent", "claude-cli/2.1.0")
		r.Header.Set(SessionHeader, id)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		call := s.Recent()[0]
		transcript, err := sessions.GatewayTranscript(usage.AgentOf("claude-cli/2.1.0"), id)
		if w.Code != status || err != nil || w.Header().Get(ArchiveHeader) == "" ||
			call.RequestBody == "" || (transcript.Captured == 1) != unmasked {
			t.Fatalf("capture must follow the actual route: status=%d recent=%t archive=%t sessions=%d error=%v",
				w.Code, call.RequestBody != "", w.Header().Get(ArchiveHeader) != "", transcript.Captured, err)
		}
		if !unmasked && (strings.Contains(call.RequestBody, second) ||
			!strings.Contains(call.RequestBody, secondMask) || call.ResponseBody != "") {
			t.Fatal("Recent Calls should keep only the protected request")
		}
		if !unmasked {
			archivePending.Wait()
			path := filepath.Join(settings.Dir(), "request-archive", filepath.FromSlash(call.Archive)+".json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var archived Archived
			if err := json.Unmarshal(data, &archived); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(archived.Request.Body, second) || !strings.Contains(archived.Request.Body, secondMask) || archived.Response.Body != "" {
				t.Fatal("archive should keep only the protected request")
			}
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if len(o.attempts) != 1 || (o.attempts[0].BodyOut != "") != unmasked {
			t.Fatalf("observer did not follow the same capture decision: %+v", o.attempts)
		}
	}
	check("hosted-protected", http.StatusOK, false)
	f.code = http.StatusBadRequest
	check("hosted-protected-error", http.StatusBadRequest, false)
	f.code = 0
	p, err := provider.Find("fake")
	if err != nil {
		t.Fatal(err)
	}
	p.Unredacted = true
	if err := provider.Save(*p); err != nil {
		t.Fatal(err)
	}
	check("hosted-opted-out", http.StatusOK, true)
}
