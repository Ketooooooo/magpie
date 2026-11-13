package privacyengine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/privacyengine/internal/redact"
)

func TestTaskReplyRestoresOnlyItsOwnEngineAndValues(t *testing.T) {
	first, _ := redact.Mask("first@privacy-boundary.internal", redact.Options{Personal: true})
	second, _ := redact.Mask("second@privacy-boundary.internal", redact.Options{Personal: true})
	if first == "first@privacy-boundary.internal" || second == "second@privacy-boundary.internal" {
		t.Fatal("fixture values were not masked")
	}
	var tasks Tasks
	tasks.Remember("native", Builtin, []gwmw.Hit{{Placeholder: first}})
	tasks.Remember("hosted", "hosted", []gwmw.Hit{{Placeholder: first}})
	for _, key := range []string{"native", "hosted", "unknown"} {
		out := httptest.NewRecorder()
		w, done := tasks.WrapReply(out, key)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"prompt":"` + first + " " + second + `"}`))
		done()
		if !strings.Contains(out.Body.String(), second) ||
			strings.Contains(out.Body.String(), "first@privacy-boundary.internal") != (key == "native") {
			t.Fatalf("%s restored the wrong values: %s", key, out.Body)
		}
	}
}
