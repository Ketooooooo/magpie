package privacyengine

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginRestoresLongMaskAcrossStreamEvents(t *testing.T) {
	const token = "{{EMAIL_abcdefghijkl}}"
	const original = "demo@example.test"
	m := newPluginMasker(t.Context(), "Local detector", nil)
	m.values[token] = original
	for _, split := range []int{1, len(token) - 1} {
		reply := httptest.NewRecorder()
		reply.Header().Set("Content-Type", "text/event-stream")
		w, done := m.Writer(reply)
		for _, part := range []string{token[:split], token[split:]} {
			fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", part)
		}
		done()
		if !strings.Contains(reply.Body.String(), original) {
			t.Errorf("token split at byte %d was not restored: %s", split, reply.Body)
		}
	}
}

func TestPluginRestoresNativePlainText(t *testing.T) {
	const token, original = "{{SECRET_abcdefgh}}", "demo\"value"
	m := newPluginMasker(t.Context(), "Local detector", nil)
	m.values[token] = original
	reply := httptest.NewRecorder()
	reply.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w, done := m.Writer(reply)
	fmt.Fprint(w, "Contact: "+token)
	done()
	if reply.Body.String() != "Contact: "+original {
		t.Fatalf("native plain text was not restored: %s", reply.Body)
	}
	mislabeled := httptest.NewRecorder()
	mislabeled.Header().Set("Content-Type", "text/plain")
	w, done = m.Writer(mislabeled)
	fmt.Fprintf(w, `{"contact":%q}`, token)
	done()
	var body map[string]string
	if err := json.Unmarshal(mislabeled.Body.Bytes(), &body); err != nil || body["contact"] != original {
		t.Fatalf("mislabeled JSON was not restored as JSON: %s", mislabeled.Body)
	}
}
