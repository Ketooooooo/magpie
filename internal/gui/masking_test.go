package gui

import (
	"encoding/json"
	"github.com/yetone/magpie/internal/privacyengine"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/maskrec"
	"github.com/yetone/magpie/internal/settings"
)

// Settings → Privacy reads what masking swapped: the summary, the records
// newest first, one record, and a value only while the masker remembers
// it; a placeholder it never made says nothing.
func TestMaskingRecordsAPI(t *testing.T) {
	const key = "sk-proj-abcdEFGH1234ijklMNOP5678qrst"
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(h, ".cache"))
	if err := settings.Save(settings.Settings{Redact: true}); err != nil {
		t.Fatal(err)
	}
	defer privacyengine.EnableBuiltin()()
	sent, hits := privacyengine.BuiltinForTest().TextHits("my key is " + key)
	if len(hits) != 1 || strings.Contains(sent, key) {
		t.Fatalf("masked %q %+v", sent, hits)
	}
	p := hits[0].Placeholder
	rec := maskrec.Add(maskrec.Record{What: "chat", Agent: "claude", Provider: "anthropic", N: 1,
		Values: []maskrec.Value{{Placeholder: p, Kind: hits[0].Kind, By: hits[0].By, Head: hits[0].Head, Len: hits[0].Len}},
		Snips:  map[string]string{p: sent}})
	other := maskrec.Add(maskrec.Record{What: "search", N: 1, Values: []maskrec.Value{{Placeholder: "{{EMAIL_00000000}}", Kind: "EMAIL", By: "rule"}}})

	srv := webPageHandler(t, webHost{func() {}}, nil)
	get := func(path string, into any) int {
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, httptest.NewRequest("GET", path, nil))
		if into != nil && rw.Code == http.StatusOK {
			if err := json.Unmarshal(rw.Body.Bytes(), into); err != nil {
				t.Fatalf("%s: %v %s", path, err, rw.Body)
			}
		}
		return rw.Code
	}
	var sum maskrec.Summary
	if get("/api/masking/summary?days=7", &sum); sum.Requests < 2 || len(sum.Days) != 7 {
		t.Fatalf("summary %+v", sum)
	}
	found := false
	for _, value := range sum.Values {
		if value.Placeholder == p {
			found = value.RecordKey == rec.Key
		}
	}
	if !found {
		t.Fatal("masking summary must identify the record for its value preview")
	}
	var page struct {
		Records []maskedRecord `json:"records"`
		More    bool           `json:"more"`
	}
	page.Records, page.More = nil, false
	if get("/api/masking/records?limit=1", &page); len(page.Records) != 1 || !page.More || page.Records[0].Key != other.Key {
		t.Fatalf("first page %+v", page)
	}
	page.Records, page.More = nil, false
	if get("/api/masking/records?limit=5&before="+strconv.FormatInt(other.Key, 10), &page); len(page.Records) == 0 || page.Records[0].Key != rec.Key || !page.Records[0].Values[0].Known {
		t.Fatalf("next page %+v", page)
	}
	page.Records, page.More = nil, false
	if get("/api/masking/records?kind=EMAIL", &page); len(page.Records) == 0 || page.Records[0].Key != other.Key || page.Records[0].Values[0].Known {
		t.Fatalf("by kind %+v", page)
	}
	var one maskedRecord
	if get("/api/masking/record?key="+strconv.FormatInt(rec.Key, 10), &one); one.Snips[p] != sent || !one.Values[0].Known {
		t.Fatalf("record %+v", one)
	}
	// the key goes as a string: a JS number holds a nanosecond key only
	// to 256ns, and the rounded key found no record
	for _, path := range []string{"/api/masking/record?key=" + strconv.FormatInt(rec.Key, 10), "/api/masking/records?limit=1"} {
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, httptest.NewRequest("GET", path, nil))
		if !strings.Contains(rw.Body.String(), `"key":"`) {
			t.Fatalf("%s: key not a string: %s", path, rw.Body)
		}
	}
	if code := get("/api/masking/record?key=1", nil); code != http.StatusNotFound {
		t.Fatalf("no such record: %d", code)
	}

	// the request as it went, and the values to read it as it came
	body := `{"messages":[{"role":"user","content":"` + sent + `"}]}`
	whole := maskrec.Add(maskrec.Record{What: "chat", N: 1, Sent: body,
		Values: []maskrec.Value{{Placeholder: p, Kind: hits[0].Kind, By: hits[0].By, Len: hits[0].Len}}})
	var got struct{ Body string }
	if get("/api/masking/sent?key="+strconv.FormatInt(whole.Key, 10), &got); got.Body != body {
		t.Fatalf("sent %q", got.Body)
	}
	if code := get("/api/masking/sent?key="+strconv.FormatInt(rec.Key, 10), nil); code != http.StatusNotFound {
		t.Fatalf("a record kept without its body: %d", code)
	}
	rw := httptest.NewRecorder()
	srv.ServeHTTP(rw, httptest.NewRequest("POST", "/api/masking/values", strings.NewReader(`{"recordKey":"`+strconv.FormatInt(rec.Key, 10)+`","ps":["`+p+`","{{EMAIL_00000000}}"]}`)))
	var vs struct{ Values map[string]string }
	if err := json.Unmarshal(rw.Body.Bytes(), &vs); err != nil || len(vs.Values) != 1 || vs.Values[p] != key || rw.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("values %d %s %v", rw.Code, rw.Body, rw.Header())
	}

	// Clear takes every record and its text, by POST alone; what a
	// placeholder stood for stays with the masker for answers to come
	// (maxyou2090 on Discord)
	rw = httptest.NewRecorder()
	srv.ServeHTTP(rw, httptest.NewRequest("GET", "/api/masking/clear", nil))
	if rw.Code == http.StatusOK {
		t.Fatalf("GET clear: %d", rw.Code)
	}
	if get("/api/masking/records?limit=5", &page); len(page.Records) == 0 {
		t.Fatal("a GET cleared the records")
	}
	rw = httptest.NewRecorder()
	srv.ServeHTTP(rw, httptest.NewRequest("POST", "/api/masking/clear", nil))
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `"cleared":true`) {
		t.Fatalf("clear: %d %s", rw.Code, rw.Body)
	}
	page.Records, page.More = nil, false
	if get("/api/masking/records?limit=5", &page); len(page.Records) != 0 || page.More {
		t.Fatalf("records after clear %+v", page)
	}
	sum = maskrec.Summary{}
	if get("/api/masking/summary?days=30", &sum); sum.Requests != 0 {
		t.Fatalf("summary after clear %+v", sum)
	}
	for _, path := range []string{"/api/masking/record?key=" + strconv.FormatInt(rec.Key, 10), "/api/masking/sent?key=" + strconv.FormatInt(whole.Key, 10)} {
		if code := get(path, nil); code != http.StatusNotFound {
			t.Fatalf("%s after clear: %d", path, code)
		}
	}

}

// Try it under Settings › Privacy shows what a request would send: with
// Keep a key's form on, a made-up key of the same form, not a
// placeholder.
func TestMaskingPreviewKeepsKeyForm(t *testing.T) {
	const key = "sk_w3axCByTQgK1PxqPhfKTrJOLBqz6sbZv"
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(h, ".cache"))
	srv := webPageHandler(t, webHost{func() {}}, nil)
	preview := func() string {
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, httptest.NewRequest("POST", "/api/masking/preview", strings.NewReader(`{"text":"用密钥 `+key+` 部署可以吗，或用密钥 OPENAI_API_KEY=`+key+`"}`)))
		var out struct{ Text string }
		if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
			t.Fatalf("%v %s", err, rw.Body)
		}
		return out.Text
	}
	for _, shape := range []bool{false, true} {
		if err := settings.Save(settings.Settings{Redact: true, RedactShape: shape}); err != nil {
			t.Fatal(err)
		}
		got := preview()
		if strings.Contains(got, key) || strings.Contains(got, "{{") == shape || shape && (!strings.Contains(got, "=sk_") || !strings.Contains(got, "用密钥 sk_")) {
			t.Errorf("keep form %v: %q", shape, got)
		}
	}
}

// A value masked by mistake is let go from its request's record
// (yew_fence on Discord): what the placeholder stood for joins Never
// mask, beside the values already there, once whatever its case, and the
// next request sends it as written. A placeholder the masker doesn't know
// adds nothing, and a GET changes nothing.
func TestMaskingAllowFromRecord(t *testing.T) {
	const key = "sk-proj-abcdEFGH1234ijklMNOP5678qrst"
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(h, ".cache"))
	if err := settings.Save(settings.Settings{Redact: true, RedactAllow: []string{"build-01"}}); err != nil {
		t.Fatal(err)
	}
	defer privacyengine.EnableBuiltin()()
	tl := privacyengine.BuiltinForTest()
	sent, hits := tl.TextHits("my key is " + key)
	if len(hits) != 1 || strings.Contains(sent, key) {
		t.Fatalf("masked %q %+v", sent, hits)
	}
	p := hits[0].Placeholder
	rec := maskrec.Add(maskrec.Record{N: 1, Values: []maskrec.Value{{Placeholder: p, Kind: hits[0].Kind, By: hits[0].By}}})
	keyRef := strconv.FormatInt(rec.Key, 10)
	payload := func(action string) string {
		return `{"recordKey":"` + keyRef + `","actionId":"` + action + `"}`
	}
	srv := webPageHandler(t, webHost{func() {}}, nil)
	call := func(method, body string) *httptest.ResponseRecorder {
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, httptest.NewRequest(method, "/api/masking/record-action", strings.NewReader(body)))
		return rw
	}
	if rw := call("GET", ""); rw.Code == http.StatusOK {
		t.Fatalf("GET allow: %d", rw.Code)
	}
	if rw := call("POST", payload("never-mask:{{EMAIL_00000000}}")); rw.Code != http.StatusBadRequest {
		t.Fatalf("a placeholder it never made: %d %s", rw.Code, rw.Body)
	}
	if got := settings.Load().RedactAllow; len(got) != 1 {
		t.Fatalf("allow after the unknown one %q", got)
	}
	rw := call("POST", payload("never-mask:"+p))
	var st struct {
		RedactAllow []string `json:"redactAllow"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &st); rw.Code != http.StatusOK || err != nil {
		t.Fatalf("allow: %d %v %s", rw.Code, err, rw.Body)
	}
	want := []string{"build-01", key}
	if strings.Join(st.RedactAllow, "\n") != strings.Join(want, "\n") || strings.Join(settings.Load().RedactAllow, "\n") != strings.Join(want, "\n") {
		t.Fatalf("allow %q, saved %q", st.RedactAllow, settings.Load().RedactAllow)
	}
	// once: again, it is in the list already
	call("POST", payload("never-mask:"+p))
	if got := settings.Load().RedactAllow; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("allow twice %q", got)
	}
	// the next request sends it as written
	if again, hits := tl.TextHits("my key is " + key); len(hits) != 0 || !strings.Contains(again, key) {
		t.Fatalf("after allow: %q %+v", again, hits)
	}
}

func TestMaskingRecordActionUsesOriginatingEngine(t *testing.T) {
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(h, ".cache"))
	if err := settings.Save(settings.Settings{
		PrivacyEngine: "external",
		RedactActions: map[string]string{"API_KEY": "block", "EMAIL": "warn"},
	}); err != nil {
		t.Fatal(err)
	}
	builtin := maskrec.Add(maskrec.Record{Blocked: true, Values: []maskrec.Value{{Kind: "API_KEY", Action: "block"}}})
	external := maskrec.Add(maskrec.Record{
		Engine: "external", Blocked: true, Values: []maskrec.Value{{Kind: "API_KEY", Action: "block"}},
		Actions: []gwmw.RecordAction{{ID: "engine-action", Label: "Change this rule", TargetRef: "private-reference"}},
	})
	srv := webPageHandler(t, webHost{func() {}}, nil)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rw
	}
	const path = "/api/masking/record-action"
	key := strconv.FormatInt(external.Key, 10)
	detail := call("GET", "/api/masking/record?key="+key, "")
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "engine-action") ||
		strings.Contains(detail.Body.String(), "private-reference") {
		t.Fatalf("the record must expose the button without its target: %d %s", detail.Code, detail.Body)
	}
	for endpoint, payload := range map[string]string{
		"/api/settings/redact-actions": `{"actions":{}}`,
		path:                           `{"recordKey":"` + key + `","actionId":"mask-blocked-kinds"}`,
	} {
		if rw := call("POST", endpoint, payload); rw.Code == http.StatusOK || settings.Load().RedactActions["API_KEY"] != "block" {
			t.Fatalf("unexpected settings write through %s: %d %s", endpoint, rw.Code, rw.Body)
		}
	}
	for _, payload := range []string{
		`{"recordKey":"` + key + `","actionId":"engine-action"}`,
		`{"recordKey":"` + key + `","actionId":"engine-action","targetRef":"override"}`,
	} {
		if rw := call("POST", path, payload); rw.Code == http.StatusOK || settings.Load().RedactActions["API_KEY"] != "block" {
			t.Fatalf("an unavailable engine or client-supplied target must fail: %d %s", rw.Code, rw.Body)
		}
	}
	key = strconv.FormatInt(builtin.Key, 10)
	body := `{"recordKey":"` + key + `","actionId":"mask-blocked-kinds"}`
	if rw := call("POST", path, body); rw.Code != http.StatusOK {
		t.Fatalf("a record from the previous engine should still work: %d %s", rw.Code, rw.Body)
	}
	if s := settings.Load(); s.RedactActions["API_KEY"] != "" || s.RedactActions["EMAIL"] != "warn" || s.PrivacyEngine != "external" {
		t.Fatalf("wrong settings after the record action: %v, engine %q", s.RedactActions, s.PrivacyEngine)
	}
	if rw := call("POST", path, body); rw.Code == http.StatusOK {
		t.Fatal("the same historical block cannot change a category that no longer blocks")
	}
}
