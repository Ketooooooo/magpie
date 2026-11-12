package redact

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatNoticeSkipsNonTextOutput(t *testing.T) {
	const mask = "{{EMAIL_abcdefgh}}"
	const value = "case@example.org"
	restore := func(s string, _ bool, counts map[string]int) string {
		if count := strings.Count(s, mask); counts != nil && count > 0 {
			counts[mask] += count
		}
		return strings.ReplaceAll(s, mask, value)
	}
	for _, test := range []struct{ name, message, finish string }{
		{"JSON", `{"content":"{\"contact\":\"` + mask + `\"}"}`, "stop"},
		{"tool call", `{"content":"Contact: ` + mask + `","tool_calls":[{"function":{"arguments":"{\"pattern\":\"` + mask + `\"}"}}]}`, "tool_calls"},
		{"reasoning only", `{"content":"Done.","reasoning_content":"Contact: ` + mask + `"}`, "stop"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := httptest.NewRecorder()
			writer := NewRestoringWriter(reply, restore, nil, func(map[string]int) string {
				t.Error("non-chat content must not render a notice")
				return ""
			})
			body := `{"choices":[{"index":0,"message":` + test.message + `,"finish_reason":"` + test.finish + `"}]}`
			writer.Write([]byte(body))
			writer.Finish()
			if got := reply.Body.Bytes(); !json.Valid(got) || !strings.Contains(string(got), value) || strings.Contains(string(got), mask) {
				t.Fatalf("expected valid restored output, got %s", got)
			}
		})
	}
}
