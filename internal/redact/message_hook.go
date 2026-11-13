package redact

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/yetone/magpie/internal/responsesstream"
)

var errMessageHook = errors.New("the privacy engine could not restore the reply")

type messageField struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	Finish    bool   `json:"finish"`
	Arguments bool   `json:"arguments"`
}

type messageResult struct {
	Text         string            `json:"text"`
	Restorations map[string]string `json:"restorations"`
}

type messageHook struct {
	reply        func(any, any) error
	fields       map[string]bool
	chatFinished map[string]bool
	args         map[string]*strings.Builder
	size         int
	notice       *chatNotice
	values       map[string]string
	put          map[string]int
	failed       bool
	extra        map[string]any
	sequence     responsesstream.Numbering
}

func NewMessageWriter(w http.ResponseWriter, reply func(any, any) error, notice bool) *Writer {
	h := &messageHook{reply: reply, put: map[string]int{}, fields: map[string]bool{}, chatFinished: map[string]bool{}, args: map[string]*strings.Builder{}}
	if notice {
		h.values = map[string]string{}
		h.notice = &chatNotice{render: func(map[string]int) string { return FormatReplyNotice(h.values) }}
	}
	return &Writer{w: w, messages: h}
}

// apply has one outstanding batch on the request's channel. A slow engine
// pauses the upstream reader through Writer.Write.
func (h *messageHook) apply(fields []messageField) ([]messageResult, error) {
	var results []messageResult
	if len(fields) == 0 {
		return results, nil
	}
	if err := h.reply(fields, &results); err != nil || len(results) != len(fields) {
		h.failed = true
		return nil, errMessageHook
	}
	return results, nil
}

func (h *messageHook) record(field messageField, result messageResult) {
	if h.notice != nil && (field.ID == "content" || field.ID == "chat/0/content") && !h.notice.skip {
		count := map[string]int{}
		for mask, value := range result.Restorations {
			count[mask]++
			h.values[mask] = value
		}
		h.notice.record(field.Text, result.Text, count, h.put)
	} else {
		for mask := range result.Restorations {
			h.put[mask]++
		}
	}
}

// editFields passes JSON string values to the engine and writes its results
// back at the same paths. Nested tool JSON is marked for the engine to decode.
func (h *messageHook) editFields(data []byte) ([]byte, error) {
	typ := typeOf(data)
	signed, args, _ := scan(data)
	protocol := replyEnvelope(data, typ)
	eligible := func(path, key, text string) bool {
		if text == "" && protocol && asJSON(key, typ) {
			return false // a tool start can carry an empty arguments string
		}
		return !sealedText(key, text) && !privateReplyField(path, key, typ, protocol, signed, args)
	}
	var fields []messageField
	_, ok := walk(data, func(path, key, text string) string {
		if eligible(path, key, text) {
			id := path
			if path == chatMessageText {
				id = "content"
			}
			fields = append(fields, messageField{ID: id, Text: text, Finish: true, Arguments: protocol && asJSON(key, typ)})
		}
		return text
	})
	if !ok {
		return data, nil
	}
	results, err := h.apply(fields)
	if err != nil {
		return nil, err
	}
	at := 0
	out, _ := walk(data, func(path, key, text string) string {
		if !eligible(path, key, text) {
			return text
		}
		f, result := fields[at], results[at]
		at++
		h.record(f, result)
		return result.Text
	})
	return out, nil
}

func (h *messageHook) event(data []byte) ([]byte, error) {
	if !json.Valid(data) {
		return nil, errMessageHook
	}
	if gjson.GetBytes(data, "choices").IsArray() {
		return h.chat(data)
	}
	switch typ := typeOf(data); typ {
	case "content_block_start":
		if gjson.GetBytes(data, "content_block.thinking").Exists() || gjson.GetBytes(data, "content_block.signature").Exists() {
			return data, nil
		}
		return h.editFields(data)
	case "content_block_delta":
		id := "block/" + gjson.GetBytes(data, "index").String()
		d := gjson.GetBytes(data, "delta")
		switch d.Get("type").String() {
		case "text_delta":
			return h.streamField(data, id, "delta.text", false)
		case "input_json_delta":
			return h.streamField(data, id, "delta.partial_json", true)
		}
		return data, nil // Anthropic thinking/signatures must replay byte for byte.
	case "content_block_stop":
		id := "block/" + gjson.GetBytes(data, "index").String()
		err := h.finishField(id, func(text string, arguments bool) map[string]any {
			kind, key := "text_delta", "text"
			if arguments {
				kind, key = "input_json_delta", "partial_json"
			}
			return map[string]any{"type": "content_block_delta", "index": gjson.GetBytes(data, "index").Int(), "delta": map[string]string{"type": kind, key: text}}
		})
		return data, err
	case "response.output_text.delta", "response.refusal.delta",
		"response.reasoning_summary_text.delta", "response.reasoning_text.delta",
		"response.function_call_arguments.delta", "response.custom_tool_call_input.delta":
		return h.streamField(data, responseFieldID(data, typ), "delta", typ == "response.function_call_arguments.delta")
	case "response.output_text.done", "response.refusal.done",
		"response.reasoning_summary_text.done", "response.reasoning_text.done",
		"response.custom_tool_call_input.done":
		// A done frame repeats the complete field. Restore that copy and
		// flush any held tail as a delta immediately before it.
		id := responseFieldID(data, typ)
		finish := func(text string, _ bool) map[string]any {
			return responseDelta(data, strings.TrimSuffix(typ, ".done")+".delta", text)
		}
		if err := h.finishField(id, finish); err != nil {
			return nil, err
		}
		return h.editFields(data)
	case "response.function_call_arguments.done":
		return h.responseArgumentsDone(data, "arguments")
	case "response.output_item.done":
		if gjson.GetBytes(data, "item.type").String() == "function_call" {
			return h.responseArgumentsDone(data, "item.arguments")
		}
		return h.editFields(data)
	default:
		if gjson.GetBytes(data, "candidates").IsArray() {
			return h.gemini(data)
		}
		return h.editFields(data)
	}
}

func responseFieldID(data []byte, typ string) string {
	if strings.HasPrefix(typ, "response.function_call_arguments.") {
		return "response/function/" + responseCallKey(data)
	}
	return strings.TrimSuffix(strings.TrimSuffix(typ, ".delta"), ".done") + "/" + gjson.GetBytes(data, "item_id").String() + "/" +
		gjson.GetBytes(data, "output_index").String() + "/" + gjson.GetBytes(data, "content_index").String() + "/" + gjson.GetBytes(data, "summary_index").String()
}

func responseCallKey(data []byte) string {
	id := gjson.GetBytes(data, "item_id").String()
	if id == "" {
		id = gjson.GetBytes(data, "item.id").String()
	}
	index := gjson.GetBytes(data, "output_index").Raw
	if index == "" {
		index = "null"
	}
	return responsesstream.CallKey(id, index)
}

func responseDelta(data []byte, typ, text string) map[string]any {
	delta := map[string]any{"type": typ, "delta": text}
	for _, key := range []string{"item_id", "output_index", "content_index", "summary_index", "sequence_number"} {
		if field := gjson.GetBytes(data, key); field.Exists() {
			delta[key] = json.RawMessage(field.Raw)
		}
	}
	if _, ok := delta["item_id"]; !ok {
		if id := gjson.GetBytes(data, "item.id"); id.Type == gjson.String {
			delta["item_id"] = json.RawMessage(id.Raw)
		}
	}
	return delta
}

func (h *messageHook) responseArgumentsDone(data []byte, path string) ([]byte, error) {
	const delta = "response.function_call_arguments.delta"
	id := responseFieldID(data, delta)
	if h.args[id] == nil {
		return h.editFields(data)
	}
	snapshot := gjson.GetBytes(data, path)
	if snapshot.Type != gjson.String {
		if err := h.finishField(id, func(text string, _ bool) map[string]any {
			return responseDelta(data, delta, text)
		}); err != nil {
			return nil, err
		}
		return h.editFields(data)
	}
	args := responsesstream.PickArgs(h.takeArguments(id), snapshot.String())
	out, err := h.editFields(replaceString(data, snapshot, args))
	if err != nil {
		return nil, err
	}
	if text := gjson.GetBytes(out, path).String(); text != "" {
		h.extra = responseDelta(data, delta, text)
	}
	return out, nil
}

func (h *messageHook) streamField(data []byte, id, path string, arguments bool) ([]byte, error) {
	field := gjson.GetBytes(data, path)
	if field.Type != gjson.String {
		return data, nil
	}
	if arguments {
		if err := h.addArguments(id, field.String()); err != nil {
			return nil, err
		}
		return replaceString(data, field, ""), nil
	}
	fields := []messageField{{ID: id, Text: field.String()}}
	results, err := h.apply(fields)
	if err != nil {
		return nil, err
	}
	h.fields[id] = true
	h.record(fields[0], results[0])
	return replaceString(data, field, results[0].Text), nil
}

func (h *messageHook) addArguments(id, text string) error {
	h.size += len(text)
	if h.size > 2<<20 {
		return errors.New("tool arguments exceed the message hook limit")
	}
	if h.args[id] == nil {
		h.args[id] = &strings.Builder{}
	}
	h.args[id].WriteString(text)
	return nil
}

func (h *messageHook) takeArguments(id string) string {
	if args := h.args[id]; args != nil {
		delete(h.args, id)
		h.size -= args.Len()
		return args.String()
	}
	return ""
}

func (h *messageHook) finishField(id string, event func(string, bool) map[string]any) error {
	field := messageField{ID: id, Finish: true}
	if h.args[id] != nil {
		field.Text, field.Arguments = h.takeArguments(id), true
	} else if h.fields[id] {
		delete(h.fields, id)
	} else {
		return nil
	}
	results, err := h.apply([]messageField{field})
	if err != nil {
		return err
	}
	h.record(field, results[0])
	if results[0].Text != "" {
		h.extra = event(results[0].Text, field.Arguments)
	}
	return nil
}

func replaceString(data []byte, field gjson.Result, text string) []byte {
	return rebuild(data[:field.Index], mustJSON(text), data[field.Index+len(field.Raw):])
}

func (h *messageHook) chat(data []byte) ([]byte, error) {
	choices := gjson.GetBytes(data, "choices").Array()
	seen := h.notice.choice(data, "delta")
	for i := len(choices) - 1; i >= 0; i-- {
		path := "choices." + strconv.Itoa(i)
		choice := gjson.GetBytes(data, path)
		part := gjson.GetBytes(data, path+".delta")
		finished := choice.Get("finish_reason").String() != ""
		if !part.IsObject() && !finished {
			continue
		}
		base := "chat/" + choice.Get("index").String() + "/"
		if h.chatFinished[base] {
			continue
		}
		if finished {
			h.chatFinished[base] = true
		}
		delta := map[string]json.RawMessage{}
		if part.IsObject() {
			if err := json.Unmarshal([]byte(part.Raw), &delta); err != nil {
				return nil, err
			}
		}
		var fields []messageField
		for _, key := range []string{"content", "reasoning_content", "reasoning", "refusal"} {
			text, id := part.Get(key), base+key
			if text.Type == gjson.String || finished && h.fields[id] {
				fields = append(fields, messageField{ID: id, Text: text.String(), Finish: finished})
				if finished {
					delete(h.fields, id)
				} else {
					h.fields[id] = true
				}
			}
		}
		nText := len(fields)
		var tools []map[string]json.RawMessage
		if raw := delta["tool_calls"]; len(raw) > 0 && json.Unmarshal(raw, &tools) != nil {
			return nil, errors.New("invalid tool call delta")
		}
		capture := func(fn map[string]json.RawMessage, id string) error {
			if raw := fn["arguments"]; len(raw) > 0 && string(raw) != "null" {
				var text string
				if err := json.Unmarshal(raw, &text); err != nil {
					return err
				}
				delete(fn, "arguments")
				return h.addArguments(id, text)
			}
			return nil
		}
		for _, tool := range tools {
			var idx int
			if err := json.Unmarshal(tool["index"], &idx); err != nil || idx < 0 || idx >= 128 {
				return nil, errors.New("invalid tool call index")
			}
			var fn map[string]json.RawMessage
			if raw := tool["function"]; len(raw) > 0 {
				if err := json.Unmarshal(raw, &fn); err != nil {
					return nil, err
				}
				if err := capture(fn, base+strconv.Itoa(idx)); err != nil {
					return nil, err
				}
				tool["function"] = mustJSON(fn)
			}
		}
		var legacy map[string]json.RawMessage
		if raw := delta["function_call"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &legacy); err != nil {
				return nil, err
			}
			if err := capture(legacy, base+"legacy"); err != nil {
				return nil, err
			}
			delta["function_call"] = mustJSON(legacy)
		}
		if finished {
			var ids []string
			for id := range h.args {
				if strings.HasPrefix(id, base) {
					ids = append(ids, id)
				}
			}
			slices.Sort(ids)
			reason := choice.Get("finish_reason").String()
			for _, id := range ids {
				text := h.takeArguments(id)
				if reason == "tool_calls" || reason == "function_call" {
					fields = append(fields, messageField{ID: id, Text: text, Arguments: true, Finish: true})
				}
			}
		}
		results, err := h.apply(fields)
		if err != nil {
			return nil, err
		}
		for i, result := range results {
			field := fields[i]
			h.record(field, result)
			key := strings.TrimPrefix(field.ID, base)
			if i < nText {
				delta[key] = mustJSON(result.Text)
			} else if key == "legacy" {
				if legacy == nil {
					legacy = map[string]json.RawMessage{}
				}
				legacy["arguments"] = mustJSON(result.Text)
				delta["function_call"] = mustJSON(legacy)
			} else {
				tools = append(tools, map[string]json.RawMessage{"index": json.RawMessage(key), "function": mustJSON(map[string]string{"arguments": result.Text})})
			}
		}
		if len(tools) > 0 {
			delta["tool_calls"] = mustJSON(tools)
		}
		if len(fields) > 0 || len(tools) > 0 || legacy != nil {
			if part.Index > 0 {
				data = rebuild(data[:part.Index], mustJSON(delta), data[part.Index+len(part.Raw):])
			} else {
				var end map[string]json.RawMessage
				if err := json.Unmarshal([]byte(choice.Raw), &end); err != nil {
					return nil, err
				}
				end["delta"] = mustJSON(delta)
				data = rebuild(data[:choice.Index], mustJSON(end), data[choice.Index+len(choice.Raw):])
			}
		}
	}
	if !seen.Exists() {
		seen = h.notice.choice(data, "delta")
	}
	return h.notice.append(data, seen, "delta"), nil
}

// Gemini's text chunks have no separate done event for each part. On a
// candidate's finish frame, release its remaining text before finishReason.
func (h *messageHook) gemini(data []byte) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var candidates []map[string]json.RawMessage
	if err := json.Unmarshal(root["candidates"], &candidates); err != nil {
		return nil, err
	}
	for i, candidate := range candidates {
		var content map[string]json.RawMessage
		if raw := candidate["content"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &content); err != nil {
				return nil, err
			}
		}
		var parts []map[string]json.RawMessage
		if raw := content["parts"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &parts); err != nil {
				return nil, err
			}
		}
		index := strconv.Itoa(i)
		if raw := candidate["index"]; len(raw) > 0 {
			index = string(raw)
		}
		prefix := "gemini/" + index + "/"
		finish := len(candidate["finishReason"]) > 0 && string(candidate["finishReason"]) != "null"
		var fields []messageField
		var destinations []map[string]json.RawMessage
		for _, part := range parts {
			if len(part["thoughtSignature"]) > 0 || len(part["thought_signature"]) > 0 {
				continue
			}
			var text string
			if json.Unmarshal(part["text"], &text) != nil {
				continue
			}
			kind := ""
			if string(part["thought"]) == "true" {
				kind = "true"
			}
			id := prefix + kind
			// Consecutive parts of the same kind belong to one text stream.
			fields = append(fields, messageField{ID: id, Text: text})
			destinations = append(destinations, part)
			h.fields[id] = true
		}
		if finish {
			var ids []string
			for id := range h.fields {
				if strings.HasPrefix(id, prefix) {
					ids = append(ids, id)
				}
			}
			slices.Sort(ids)
			for _, id := range ids {
				delete(h.fields, id)
				part := map[string]json.RawMessage{}
				if strings.HasSuffix(id, "/true") {
					part["thought"] = json.RawMessage("true")
				}
				fields = append(fields, messageField{ID: id, Finish: true})
				destinations = append(destinations, part)
				parts = append(parts, part)
			}
		}
		results, err := h.apply(fields)
		if err != nil {
			return nil, err
		}
		// Rebuild any complete argument objects using the same JSON hook.
		if len(parts) > 0 && content == nil {
			content = map[string]json.RawMessage{"role": json.RawMessage(`"model"`)}
		}
		if content != nil {
			for _, part := range parts {
				if call, ok := part["functionCall"]; ok && len(part["thoughtSignature"]) == 0 && len(part["thought_signature"]) == 0 {
					var function map[string]json.RawMessage
					if err := json.Unmarshal(call, &function); err != nil {
						return nil, err
					}
					if args := function["args"]; len(args) > 0 {
						out, err := h.editFields(args)
						if err != nil {
							return nil, err
						}
						function["args"] = out
					}
					part["functionCall"] = mustJSON(function)
				}
			}
			for j, result := range results {
				h.record(fields[j], result)
				destinations[j]["text"] = mustJSON(result.Text)
			}
			content["parts"] = mustJSON(parts)
			candidate["content"] = mustJSON(content)
		}
	}
	root["candidates"] = mustJSON(candidates)
	return mustJSON(root), nil
}

func (h *messageHook) whole(data []byte, contentType string) ([]byte, error) {
	if strings.HasPrefix(strings.ToLower(contentType), "text/plain") && !json.Valid(data) {
		out, err := RestoreMessage(h.reply, string(data), false)
		return []byte(out), err
	}
	choice := h.notice.choice(data, "message")
	out, err := h.editFields(data)
	if err != nil {
		return nil, err
	}
	return h.notice.append(out, choice, "message"), nil
}

func RestoreMessage(reply func(any, any) error, text string, arguments bool) (string, error) {
	var results []messageResult
	if err := reply([]messageField{{Text: text, Finish: true, Arguments: arguments}}, &results); err != nil || len(results) != 1 {
		return text, errMessageHook
	}
	return results[0].Text, nil
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func (rw *Writer) messageEvent(ev []byte) error {
	_, data, pre, post, ok := splitEvent(ev)
	if !ok || string(data) == "[DONE]" {
		if (len(rw.messages.fields) > 0 || len(rw.messages.args) > 0) && strings.Contains(string(ev), "data: [DONE]") {
			return rw.messageError()
		}
		_, err := rw.w.Write(ev)
		return err
	}
	out, err := rw.messages.event(data)
	if err != nil {
		return rw.messageError()
	}
	h := rw.messages
	if extra := h.extra; extra != nil {
		h.extra = nil
		prefix := []byte("event: " + extra["type"].(string) + "\ndata: ")
		data := mustJSON(extra)
		if numbered := h.sequence.Number(data); numbered != nil {
			data = numbered
		}
		if _, err := rw.w.Write(rebuild(prefix, data, []byte("\n\n"))); err != nil {
			return err
		}
	}
	if strings.HasPrefix(gjson.GetBytes(out, "type").String(), "response.") {
		if numbered := h.sequence.Number(out); numbered != nil {
			out = numbered
		}
	}
	_, err = rw.w.Write(rebuild(pre, out, post))
	return err
}

func (rw *Writer) messageError() error {
	rw.messages.failed = true
	_, _ = rw.w.Write([]byte("data: {\"error\":{\"message\":\"The privacy engine could not restore the reply\"}}\n\n"))
	rw.Flush()
	return errMessageHook
}
