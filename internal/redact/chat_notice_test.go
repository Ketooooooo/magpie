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
	restore := func(input, output any) error {
		for _, field := range input.([]messageField) {
			result := messageResult{Text: strings.ReplaceAll(field.Text, mask, value)}
			if result.Text != field.Text {
				result.Restorations = map[string]string{mask: value}
			}
			out := output.(*[]messageResult)
			*out = append(*out, result)
		}
		return nil
	}
	for _, test := range []struct{ name, message, finish string }{
		{"JSON", `{"content":"{\"contact\":\"` + mask + `\"}"}`, "stop"},
		{"tool call", `{"content":"Contact: ` + mask + `","tool_calls":[{"function":{"arguments":"{\"pattern\":\"` + mask + `\"}"}}]}`, "tool_calls"},
		{"reasoning only", `{"content":"Done.","reasoning_content":"Contact: ` + mask + `"}`, "stop"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := httptest.NewRecorder()
			writer := NewMessageWriter(reply, restore, true)
			body := `{"choices":[{"index":0,"message":` + test.message + `,"finish_reason":"` + test.finish + `"}]}`
			writer.Write([]byte(body))
			writer.Finish()
			if got := reply.Body.Bytes(); !json.Valid(got) || !strings.Contains(string(got), value) || strings.Contains(string(got), mask) || strings.Contains(string(got), replyNoticeTarget) {
				t.Fatalf("expected valid restored output, got %s", got)
			}
		})
	}
}
