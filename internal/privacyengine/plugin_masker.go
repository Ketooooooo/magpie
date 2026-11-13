package privacyengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/redact"
)

func pluginPreview(ctx context.Context, input, name string, protect protectBatch) (string, []gwmw.Hit, bool, error) {
	type result struct {
		text string
		hits []gwmw.Hit
	}
	m := newPluginMasker(ctx, name, protect)
	out, err := gwmw.Safely(func() result {
		text, hits := m.TextHitsContext(ctx, input)
		return result{text, hits}
	})
	return out.text, out.hits, false, err
}

type protectBatch func(context.Context, []redact.Fragment) ([]scanReport, error)

// A masker protects one batch before its restoration map is used by Writer.
type pluginMasker struct {
	name        string
	scan        protectBatch
	ctx         context.Context
	values      map[string]string
	masks       map[byte][]maskSpelling
	escaped     map[byte][]maskSpelling
	replyNotice bool
}

func newPluginMasker(ctx context.Context, name string, scan protectBatch) *pluginMasker {
	return &pluginMasker{name: name, scan: scan, ctx: ctx, values: map[string]string{}}
}

type scanReport struct {
	Complete  bool   `json:"complete"`
	Protected string `json:"protected_text"`
	Changes   []struct {
		Start      int    `json:"start"`
		End        int    `json:"end"`
		Value      string `json:"value"`
		Mask       string `json:"placeholder"`
		Category   string `json:"category"`
		By         string `json:"by"`
		Reversible bool   `json:"reversible"`
	} `json:"changes"`
}

func (m *pluginMasker) protect(ctx context.Context, fragments []redact.Fragment) ([]string, []gwmw.Hit) {
	var pending []redact.Fragment
	indexes := map[redact.Fragment]int{}
	for _, fragment := range fragments {
		if _, seen := indexes[fragment]; fragment.Text != "" && !seen {
			indexes[fragment] = len(pending)
			pending = append(pending, fragment)
		}
	}
	var reports []scanReport
	if len(pending) > 0 {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		var err error
		reports, err = m.scan(ctx, pending)
		if err != nil {
			panic(err)
		}
		if len(reports) != len(pending) {
			panic(errors.New("The privacy plugin returned a different batch"))
		}
	}
	var hits []gwmw.Hit
	texts := make([]string, 0, len(fragments))
	for _, f := range fragments {
		if f.Text == "" {
			texts = append(texts, "")
			continue
		}
		report := reports[indexes[f]]
		if !report.Complete {
			panic(errors.New("The privacy plugin could not complete protection"))
		}
		var protected strings.Builder
		last := 0
		for _, change := range report.Changes {
			if change.Start < last || change.End <= change.Start || change.End > len(f.Text) ||
				f.Text[change.Start:change.End] != change.Value {
				panic(errors.New("The privacy plugin returned an invalid replacement range"))
			}
			protected.WriteString(f.Text[last:change.Start])
			protected.WriteString(change.Mask)
			last = change.End
			if change.Reversible {
				if change.Mask == "" || !utf8.ValidString(change.Mask) {
					panic(errors.New("The privacy plugin returned an invalid reversible mask"))
				}
				if value, found := m.values[change.Mask]; found && value != change.Value {
					panic(errors.New("The privacy plugin returned a conflicting mask"))
				}
				m.values[change.Mask] = change.Value
			}
			by := change.By
			if by == "" {
				by = "unknown"
			}
			hits = append(hits, gwmw.Hit{Kind: change.Category, By: by, Placeholder: change.Mask})
		}
		protected.WriteString(f.Text[last:])
		if protected.String() != report.Protected {
			panic(errors.New("The privacy plugin returned inconsistent protected text"))
		}
		texts = append(texts, report.Protected)
	}
	m.indexMasks()
	return texts, hits
}

func (m *pluginMasker) JSONHitsContext(ctx context.Context, body []byte) ([]byte, []gwmw.Hit) {
	var hits []gwmw.Hit
	out, ok := redact.MapFragments(body, func(fragments []redact.Fragment) []string {
		var texts []string
		texts, hits = m.protect(ctx, fragments)
		return texts
	})
	if !ok {
		panic(errors.New("The privacy plugin could not read the request"))
	}
	return out, hits
}

func (m *pluginMasker) TextHitsContext(ctx context.Context, text string) (string, []gwmw.Hit) {
	out, hits := m.TextsHitsContext(ctx, []string{text})
	return out[0], hits
}

func (m *pluginMasker) TextsHitsContext(ctx context.Context, texts []string) ([]string, []gwmw.Hit) {
	fragments := make([]redact.Fragment, len(texts))
	for i, text := range texts {
		fragments[i] = redact.Fragment{Text: text, Scope: "user"}
	}
	return m.protect(ctx, fragments)
}

func (m *pluginMasker) JSONHits(body []byte) ([]byte, []gwmw.Hit) {
	return m.JSONHitsContext(m.ctx, body)
}
func (m *pluginMasker) TextHits(s string) (string, []gwmw.Hit) { return m.TextHitsContext(m.ctx, s) }
func (m *pluginMasker) JSON(b []byte) ([]byte, int)            { out, h := m.JSONHits(b); return out, len(h) }
func (m *pluginMasker) Text(s string) (string, int)            { out, h := m.TextHits(s); return out, len(h) }
func (m *pluginMasker) Value(token string) (string, bool) {
	v, ok := m.values[token]
	return v, ok
}

func (m *pluginMasker) Restore(text string, escaped bool) string {
	return m.restore(text, escaped, nil)
}

func (m *pluginMasker) restore(text string, escaped bool, put map[string]int) string {
	var out strings.Builder
	last := 0
	m.walkMasks(text, escaped, false, func(at, length int, token string) {
		out.WriteString(text[last:at])
		value := m.values[token]
		if put != nil {
			put[token]++
		}
		if escaped {
			value = jsonStringContents(value)
		}
		out.WriteString(value)
		last = at + length
	})
	if last == 0 {
		return text
	}
	out.WriteString(text[last:])
	return out.String()
}

type maskSpelling struct {
	token, text string
}

func (m *pluginMasker) indexMasks() {
	if len(m.values) == 0 {
		return
	}
	m.masks, m.escaped = make(map[byte][]maskSpelling), make(map[byte][]maskSpelling)
	for token := range m.values {
		escaped := jsonStringContents(token)
		m.masks[token[0]] = append(m.masks[token[0]], maskSpelling{token, token})
		m.escaped[escaped[0]] = append(m.escaped[escaped[0]], maskSpelling{token, escaped})
	}
}

func jsonStringContents(text string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(text)
	return b.String()[1 : b.Len()-2]
}

// walkMasks matches the longest registered literal at each position. Streaming
// holds a suffix only where a longer mask could still complete.
func (m *pluginMasker) walkMasks(text string, escaped, hold bool, found func(int, int, string)) int {
	masks := m.masks
	if escaped {
		masks = m.escaped
	}
	for at := 0; at < len(text); {
		remaining := text[at:]
		match := ""
		matchLen := 0
		for _, mask := range masks[text[at]] {
			if hold && len(remaining) < len(mask.text) && strings.HasPrefix(mask.text, remaining) {
				return len(remaining)
			}
			if len(mask.text) > matchLen && strings.HasPrefix(remaining, mask.text) {
				match, matchLen = mask.token, len(mask.text)
			}
		}
		if matchLen == 0 {
			if escaped && text[at] == '\\' {
				// An unmatched JSON escape is a single unit. Its spelling
				// must never be mistaken for a mask such as "n" or "0".
				size := 2
				if len(remaining) > 1 && remaining[1] == 'u' {
					size = 6
				}
				at += min(size, len(remaining))
			} else {
				at++
			}
			continue
		}
		if found != nil {
			found(at, matchLen, match)
		}
		at += matchLen
	}
	return 0
}

func (m *pluginMasker) partialTail(text string, escaped bool) int {
	return m.walkMasks(text, escaped, true, nil)
}

func (m *pluginMasker) Writer(w http.ResponseWriter) (http.ResponseWriter, func()) {
	return m.replyWriter(w, false)
}

func (m *pluginMasker) WriterWithNotice(w http.ResponseWriter) (http.ResponseWriter, func()) {
	return m.replyWriter(w, true)
}

func (m *pluginMasker) replyWriter(w http.ResponseWriter, present bool) (http.ResponseWriter, func()) {
	if len(m.values) == 0 {
		return w, func() {}
	}
	var notice func(map[string]int) string
	if present && m.replyNotice {
		notice = func(put map[string]int) string {
			values := make(map[string]string, len(put))
			for token := range put {
				if value, ok := m.Value(token); ok {
					values[token] = value
				}
			}
			return redact.FormatReplyNotice(values)
		}
	}
	writer := redact.NewRestoringWriter(w, m.restore, m.partialTail, notice)
	return writer, writer.Finish
}

var _ gwmw.ContextTeller = (*pluginMasker)(nil)

func (m *pluginMasker) PrivacyName() string { return m.name }
