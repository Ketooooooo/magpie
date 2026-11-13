package redact

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestMessageHookStreamsTextAndWaitsForCompleteArguments(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "text/event-stream")
	batches := 0
	w := NewMessageWriter(rec, func(input, output any) error {
		batches++
		fields := input.([]messageField)
		switch batches {
		case 1:
			if len(fields) != 1 || fields[0].ID != "chat/0/content" || fields[0].Finish || fields[0].Text != "ready" {
				t.Fatalf("unexpected text fields: %+v", fields)
			}
			*output.(*[]messageResult) = []messageResult{{Text: "visible"}}
		case 2:
			if len(fields) != 2 || !fields[0].Finish || !fields[1].Arguments || fields[1].Text != `{"value":"mask","count":1}` {
				t.Fatalf("unexpected final fields: %+v", fields)
			}
			*output.(*[]messageResult) = []messageResult{{Text: ""}, {Text: `{"value":"original","count":1}`}}
		default:
			t.Fatal("extra batch")
		}
		return nil
	}, true)
	frame := func(delta, reason string) {
		t.Helper()
		_, err := fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":%s,\"finish_reason\":%s}]}\n\n", delta, reason)
		if err != nil {
			t.Fatal(err)
		}
	}
	frame(`{"content":"ready"}`, "null")
	if !strings.Contains(rec.Body.String(), "visible") {
		t.Fatal("first text was held")
	}
	frame(`{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"test","arguments":"{\"value\":\"ma"}}]}`, "null")
	frame(`{"tool_calls":[{"index":0,"function":{"arguments":"sk\",\"count\":1}"}}]}`, "null")
	if batches != 1 || strings.Contains(rec.Body.String(), "arguments") {
		t.Fatal("partial arguments reached the engine or client")
	}
	frame(`{}`, `"tool_calls"`)
	w.Finish()
	var args string
	for line := range strings.SplitSeq(rec.Body.String(), "\n") {
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			if !json.Valid([]byte(data)) {
				t.Fatal("invalid SSE payload")
			}
			args += gjson.Get(data, "choices.0.delta.tool_calls.0.function.arguments").String()
		}
	}
	if batches != 2 || args != `{"value":"original","count":1}` || strings.Contains(rec.Body.String(), replyNoticeTarget) {
		t.Fatalf("unexpected tool reply: %s", rec.Body)
	}
}

func TestMessageHookFinishesProtocolFields(t *testing.T) {
	for _, test := range []struct {
		name   string
		frames []string
		final  string
	}{
		{"responses", []string{
			`{"type":"response.output_text.delta","item_id":"msg","output_index":0,"content_index":0,"sequence_number":5,"delta":"mas"}`,
			`{"type":"response.output_text.delta","item_id":"msg","output_index":0,"content_index":0,"sequence_number":6,"delta":"k"}`,
			`{"type":"response.output_text.done","item_id":"msg","output_index":0,"content_index":0,"sequence_number":7,"text":"mask"}`,
		}, `"sequence_number":8,"text":"original"`},
		{"anthropic", []string{
			`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"mas"}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"k"}}`,
			`{"type":"content_block_stop","index":1}`,
		}, `"text":"original","type":"text_delta"`},
		{"gemini", []string{
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"mas"}]}}]}`,
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"k"}]}}]}`,
			`{"candidates":[{"finishReason":"STOP"}]}`,
		}, `"text":"original"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "text/event-stream")
			pending := map[string]string{}
			w := NewMessageWriter(rec, func(input, output any) error {
				for _, field := range input.([]messageField) {
					result := messageResult{}
					if field.Finish {
						result.Text = strings.ReplaceAll(pending[field.ID]+field.Text, "mask", "original")
						delete(pending, field.ID)
					} else {
						pending[field.ID] += field.Text
					}
					out := output.(*[]messageResult)
					*out = append(*out, result)
				}
				return nil
			}, false)
			for _, frame := range test.frames {
				if _, err := fmt.Fprintf(w, "data: %s\n\n", frame); err != nil {
					t.Fatal(err)
				}
			}
			w.Finish()
			got := rec.Body.String()
			if !strings.Contains(got, test.final) || strings.Contains(got, `"mas"`) || strings.Contains(got, `"mask"`) || len(pending) != 0 {
				t.Fatalf("unexpected %s reply: %s, unfinished fields %v", test.name, got, pending)
			}
			if test.name == "responses" && (!strings.Contains(got, `"delta":"original"`) || strings.Count(got, `"sequence_number":7`) != 1) {
				t.Fatalf("final text delta missing or numbered incorrectly: %s", got)
			}
		})
	}
}

func TestMessageHookUsesCompleteResponsesArguments(t *testing.T) {
	for _, test := range []struct {
		name string
		done string
		path string
	}{
		{"short arguments snapshot", `{"type":"response.function_call_arguments.done","item_id":"fc","output_index":0,"sequence_number":4,"arguments":"{}"}`, "arguments"},
		{"item snapshot only", `{"type":"response.output_item.done","output_index":0,"sequence_number":4,"item":{"type":"function_call","id":"fc","arguments":"{\"value\":\"mask\",\"count\":1}"}}`, "item.arguments"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "text/event-stream")
			w := NewMessageWriter(rec, func(input, output any) error {
				for _, field := range input.([]messageField) {
					if field.Arguments && !json.Valid([]byte(field.Text)) {
						t.Fatalf("incomplete arguments passed to the engine: %q", field.Text)
					}
					result := messageResult{Text: strings.ReplaceAll(field.Text, "mask", "original")}
					*output.(*[]messageResult) = append(*output.(*[]messageResult), result)
				}
				return nil
			}, false)
			for _, frame := range []string{
				`{"type":"response.output_item.added","output_index":0,"sequence_number":1,"item":{"type":"function_call","id":"fc","arguments":""}}`,
				`{"type":"response.function_call_arguments.delta","item_id":"fc","output_index":0,"sequence_number":2,"delta":"{\"value\":\"ma"}`,
				`{"type":"response.function_call_arguments.delta","item_id":"fc","output_index":0,"sequence_number":3,"delta":"sk\",\"count\":1}"}`,
				test.done,
				`{"type":"response.completed","sequence_number":9,"response":{"status":"completed"}}`,
			} {
				if _, err := fmt.Fprintf(w, "data: %s\n\n", frame); err != nil {
					t.Fatal(err)
				}
			}
			w.Finish()
			var deltas, done string
			var last int64
			for line := range strings.SplitSeq(rec.Body.String(), "\n") {
				data, ok := strings.CutPrefix(line, "data: ")
				if !ok {
					continue
				}
				seq := gjson.Get(data, "sequence_number").Int()
				if seq <= last {
					t.Fatalf("out of order event after %d: %s", last, data)
				}
				last = seq
				deltas += gjson.Get(data, "delta").String()
				if field := gjson.Get(data, test.path); seq == 5 && field.Exists() {
					done = field.String()
				}
			}
			const want = `{"value":"original","count":1}`
			if deltas != want || done != want || last != 9 {
				t.Fatalf("unexpected Responses stream: %s", rec.Body)
			}
		})
	}
}

func TestMessageHookIgnoresEmptyDeltasAfterFinish(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "text/event-stream")
	w := NewMessageWriter(rec, func(input, output any) error {
		for _, f := range input.([]messageField) {
			*output.(*[]messageResult) = append(*output.(*[]messageResult), messageResult{Text: f.Text})
		}
		return nil
	}, true)
	for _, frame := range []string{
		`{"choices":[{"index":0,"delta":{"content":"Hi"}}]}`,
		`{"choices":[{"index":0,"finish_reason":"stop"}]}`,
		`{"choices":[{"index":0,"delta":{"content":""}}],"usage":{"completion_tokens":1}}`,
		`[DONE]`,
	} {
		if _, err := fmt.Fprintf(w, "data: %s\n\n", frame); err != nil {
			t.Fatalf("%s: %v, output %s", frame, err, rec.Body)
		}
	}
	w.Finish()
	if strings.Contains(rec.Body.String(), "error") {
		t.Fatal(rec.Body.String())
	}
}
