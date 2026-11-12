package privacyengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/lazyre"
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
	name   string
	scan   protectBatch
	ctx    context.Context
	values map[string]string
	notice func(context.Context, map[string]string) string
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
		Reversible bool   `json:"reversible"`
	} `json:"changes"`
}

var maskToken = lazyre.New(`\{\{[A-Z0-9_]+_[a-z2-7]+\}\}`)

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
				if change.Mask == "" || maskToken.FindString(change.Mask) != change.Mask {
					panic(errors.New("The privacy plugin returned an unsupported reversible mask"))
				}
				if value, found := m.values[change.Mask]; found && value != change.Value {
					panic(errors.New("The privacy plugin returned a conflicting mask"))
				}
				m.values[change.Mask] = change.Value
			}
			hits = append(hits, gwmw.Hit{Kind: change.Category, By: "rule", Placeholder: change.Mask})
		}
		protected.WriteString(f.Text[last:])
		if protected.String() != report.Protected {
			panic(errors.New("The privacy plugin returned inconsistent protected text"))
		}
		texts = append(texts, report.Protected)
	}
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
	return maskToken.ReplaceAllStringFunc(text, func(token string) string {
		value, ok := m.Value(token)
		if !ok {
			return token
		}
		if put != nil {
			put[token]++
		}
		if escaped {
			raw, _ := json.Marshal(value)
			return string(raw[1 : len(raw)-1])
		}
		return value
	})
}

// partialTail only holds suffixes that can finish a mask from this request.
func (m *pluginMasker) partialTail(text string) int {
	last := strings.LastIndexByte(text, '{')
	if last > 0 && text[last-1] == '{' {
		tail := text[last-1:]
		for token := range m.values {
			if len(tail) < len(token) && strings.HasPrefix(token, tail) {
				return len(tail)
			}
		}
	}
	if last >= 0 && last == len(text)-1 {
		return 1
	}
	return 0
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
	if present && m.notice != nil {
		notice = func(put map[string]int) string {
			values := make(map[string]string, len(put))
			for token := range put {
				if value, ok := m.Value(token); ok {
					values[token] = value
				}
			}
			ctx, cancel := context.WithTimeout(m.ctx, time.Second)
			defer cancel()
			return m.notice(ctx, values)
		}
	}
	writer := redact.NewRestoringWriter(w, m.restore, m.partialTail, notice)
	return writer, writer.Finish
}

var _ gwmw.ContextTeller = (*pluginMasker)(nil)

func (m *pluginMasker) PrivacyName() string { return m.name }
