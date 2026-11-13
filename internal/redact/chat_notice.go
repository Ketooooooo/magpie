package redact

import (
	"encoding/json"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	chatMessageText = "choices.0.message.content"
	chatDeltaText   = "choices.0.delta.content"
	chatNoticeLimit = 256 << 10
)

// chatNotice collects just the assistant's visible text while restoration
// streams normally. The assembled text is used to rule out JSON replies.
type chatNotice struct {
	render           func(map[string]int) string
	masked, restored strings.Builder
	values           map[string]int
	skip             bool
}

func (n *chatNotice) choice(data []byte, field string) gjson.Result {
	if n == nil || n.skip {
		return gjson.Result{}
	}
	choices := gjson.GetBytes(data, "choices").Array()
	if len(choices) == 0 {
		return gjson.Result{}
	}
	choice := choices[0]
	if len(choices) != 1 || choice.Get("index").Int() != 0 {
		n.skip = true
		return gjson.Result{}
	}
	part := choice.Get(field)
	for _, key := range []string{"tool_calls", "function_call", "refusal"} {
		if value := part.Get(key); value.Exists() && value.Raw != "null" && value.Raw != "[]" && value.Raw != `""` {
			n.skip = true
			return gjson.Result{}
		}
	}
	if !part.IsObject() {
		return gjson.Result{}
	}
	return choice
}

func (n *chatNotice) record(masked, restored string, local, total map[string]int) {
	for mask, count := range local {
		total[mask] += count
	}
	if len(masked) > chatNoticeLimit-n.masked.Len() || len(restored) > chatNoticeLimit-n.restored.Len() {
		n.skip = true
		return
	}
	n.masked.WriteString(masked)
	n.restored.WriteString(restored)
	if n.values == nil {
		n.values = make(map[string]int)
	}
	for mask, count := range local {
		n.values[mask] += count
	}
}

func (n *chatNotice) append(data []byte, choice gjson.Result, field string) []byte {
	reason := choice.Get("finish_reason").String()
	if n == nil || n.skip || reason == "" {
		return data
	}
	n.skip = true // the choice ended, including length limits and tool turns
	if reason != "stop" || len(n.values) == 0 ||
		json.Valid([]byte(n.masked.String())) || json.Valid([]byte(n.restored.String())) {
		return data
	}
	notice := n.render(n.values)
	if notice == "" {
		return data
	}
	part := gjson.GetBytes(data, "choices.0."+field)
	var object map[string]json.RawMessage
	if part.Index <= 0 || !part.IsObject() || json.Unmarshal([]byte(part.Raw), &object) != nil {
		return data
	}
	object["content"], _ = json.Marshal(part.Get("content").String() + notice)
	replacement, err := json.Marshal(object)
	if err != nil {
		return data
	}
	out := make([]byte, 0, len(data)-len(part.Raw)+len(replacement))
	out = append(out, data[:part.Index]...)
	out = append(out, replacement...)
	out = append(out, data[part.Index+len(part.Raw):]...)
	return out
}
