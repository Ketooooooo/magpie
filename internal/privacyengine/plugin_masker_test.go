package privacyengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/redact"
)

func TestPluginRestoresLongMaskAcrossStreamEvents(t *testing.T) {
	const token = "{{EMAIL_abcdefghijkl}}"
	const original = "demo@example.test"
	m := newPluginMasker(t.Context(), "Local detector", nil)
	m.values[token] = original
	m.indexMasks()
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
	m.indexMasks()
	jsonReply := httptest.NewRecorder()
	jsonReply.Header().Set("Content-Type", "application/json")
	w, done := m.Writer(jsonReply)
	fmt.Fprintf(w, `{"name":%q,"status":%q}`, token, token)
	done()
	var fields map[string]string
	if err := json.Unmarshal(jsonReply.Body.Bytes(), &fields); err != nil || fields["name"] != original || fields["status"] != original {
		t.Fatalf("opaque native response fields were not restored: %s", jsonReply.Body)
	}

	reply := httptest.NewRecorder()
	reply.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w, done = m.Writer(reply)
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

func TestPluginRestoresConfiguredMasks(t *testing.T) {
	m := newPluginMasker(t.Context(), "Local detector", func(_ context.Context, fragments []redact.Fragment) ([]scanReport, error) {
		var reports []scanReport
		for _, fragment := range fragments {
			var report scanReport
			const template = `{"complete":true,"protected_text":"198.18.0.1 [[private]]","changes":[
				{"start":0,"end":7,"value":"address","placeholder":"198.18.0.1","category":"IP","reversible":true,"by":"model"},
				{"start":8,"end":14,"value":"secret","placeholder":"[[private]]","category":"SECRET","reversible":true}
			]}`
			if fragment.Text != "address secret" {
				t.Fatalf("unexpected fragment %q", fragment.Text)
			}
			if err := json.Unmarshal([]byte(template), &report); err != nil {
				t.Fatal(err)
			}
			reports = append(reports, report)
		}
		return reports, nil
	})
	protected, hits := m.TextHitsContext(t.Context(), "address secret")
	if protected != "198.18.0.1 [[private]]" || m.Restore(protected, false) != "address secret" {
		t.Fatalf("configured masks did not round-trip: %q", protected)
	}
	if len(hits) != 2 || hits[0].By != "model" || hits[1].By != "unknown" {
		t.Fatalf("incorrect hit sources: %+v", hits)
	}
}

func TestPluginConfiguredMasksStreamLikeWholeText(t *testing.T) {
	m := newPluginMasker(t.Context(), "Local detector", nil)
	m.values = map[string]string{
		"198.18.0.1": "short", "198.18.0.10": "long",
		"abcd": "198.18.0.1", "cde": "other", `x"y`: `a"b`,
		"stop": "not a finish reason", "0": "zero", "true": "not a boolean",
		"n": "letter",
	}
	m.indexMasks()
	tests := []struct {
		name, text, want string
		arguments        bool
		counts           int
	}{
		{"longer match", "198.18.0.10", "long", false, 1},
		{"uncompleted prefix", "198.18.0.1", "short", false, 1},
		{"alternate punctuation", "abcd stop", "198.18.0.1 not a finish reason", false, 2},
		{"no recursive or overlapping matches", "abcde", "198.18.0.1e", false, 1},
		{"JSON-escaped mask", `{"value":"x\"y"}`, `{"value":"a\"b"}`, true, 1},
		{"JSON primitives", `{"qty":0,"ok":true,"value":"0 true"}`, `{"qty":0,"ok":true,"value":"zero not a boolean"}`, true, 2},
		{"JSON escapes", `{"other":"\n\u0000","value":"n 0"}`, `{"other":"\n\u0000","value":"letter zero"}`, true, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for split := 1; split < len(tc.text); split++ {
				reply := httptest.NewRecorder()
				reply.Header().Set("Content-Type", "text/event-stream")
				w, done := m.Writer(reply)
				for _, part := range []string{tc.text[:split], tc.text[split:]} {
					if tc.arguments {
						fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":%q}}]}}]}\n\n", part)
					} else {
						fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", part)
					}
				}
				fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
				done()
				var output strings.Builder
				for line := range strings.SplitSeq(reply.Body.String(), "\n") {
					payload, ok := strings.CutPrefix(line, "data: ")
					if !ok || payload == "[DONE]" {
						continue
					}
					var event struct {
						Choices []struct {
							FinishReason string `json:"finish_reason"`
							Delta        struct {
								Content   string `json:"content"`
								ToolCalls []struct {
									Function struct{ Arguments string }
								} `json:"tool_calls"`
							}
						}
					}
					if err := json.Unmarshal([]byte(payload), &event); err != nil {
						t.Fatal(err)
					}
					choice := event.Choices[0]
					if choice.FinishReason != "" && choice.FinishReason != "stop" {
						t.Fatalf("the finish reason was rewritten: %s", payload)
					}
					output.WriteString(choice.Delta.Content)
					for _, call := range choice.Delta.ToolCalls {
						output.WriteString(call.Function.Arguments)
					}
				}
				if got := output.String(); got != tc.want {
					t.Fatalf("split at byte %d: got %q, want %q", split, got, tc.want)
				}
				counts := w.(*redact.Writer).Put()
				if len(counts) != tc.counts {
					t.Fatalf("split at byte %d: expected %d emitted masks, got %+v", split, tc.counts, counts)
				}
				for _, count := range counts {
					if count != 1 {
						t.Fatalf("split at byte %d: counted mask more than once: %+v", split, counts)
					}
				}
			}
		})
	}
}

func TestPluginNoticeCountsOnlyCompletedMask(t *testing.T) {
	const short, long = "198.18.0.1", "198.18.0.10"
	m := newPluginMasker(t.Context(), "Local detector", nil)
	m.values = map[string]string{short: "short secret", long: "long secret"}
	m.replyNotice = true
	m.indexMasks()
	for _, tc := range []struct{ suffix, want, other string }{
		{"0", "long secret", "short secret"},
		{"", "short secret", "long secret"},
	} {
		reply := httptest.NewRecorder()
		reply.Header().Set("Content-Type", "text/event-stream")
		w, done := m.WriterWithNotice(reply)
		fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", "Address: "+short)
		fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":%q},\"finish_reason\":\"stop\"}]}\n\n", tc.suffix)
		done()
		if got := reply.Body.String(); !strings.Contains(got, "🔒") || strings.Count(got, tc.want) != 2 || strings.Contains(got, tc.other) {
			t.Fatalf("suffix %q produced the wrong reply or notice: %s", tc.suffix, got)
		}
	}
}
