package privacyengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
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

type protectBatch func(context.Context, []redact.Fragment, *uint64) ([]scanReport, uint64, error)

type pluginMasker struct {
	name       string
	scan       protectBatch
	mu         sync.Mutex
	ctx        context.Context
	values     map[string]string
	version    *uint64
	reports    map[redact.Fragment]scanReport
	notice     func(context.Context, map[string]string) string
	chatNotice bool
}

func newPluginMasker(ctx context.Context, name string, scan protectBatch) *pluginMasker {
	return &pluginMasker{name: name, scan: scan, ctx: ctx, values: map[string]string{}, reports: map[redact.Fragment]scanReport{}}
}

type scanReport struct {
	Complete  bool    `json:"complete"`
	Protected string  `json:"protected_text"`
	Source    *string `json:"source_text"`
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
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var pending []redact.Fragment
	seen := map[redact.Fragment]bool{}
	for _, fragment := range fragments {
		if _, cached := m.reports[fragment]; fragment.Text != "" && !cached && !seen[fragment] {
			pending = append(pending, fragment)
			seen[fragment] = true
		}
	}
	if len(pending) > 0 {
		reports, version, err := m.scan(ctx, pending, m.version)
		if err != nil {
			panic(err)
		}
		if len(reports) != len(pending) || (m.version != nil && *m.version != version) {
			panic(errors.New("The privacy plugin returned a different batch or policy version"))
		}
		m.version = &version
		for i, fragment := range pending {
			m.reports[fragment] = reports[i]
		}
	}
	var hits []gwmw.Hit
	texts := make([]string, 0, len(fragments))
	for _, f := range fragments {
		if f.Text == "" {
			texts = append(texts, "")
			continue
		}
		report := m.reports[f]
		if !report.Complete {
			panic(errors.New("The privacy plugin could not complete protection"))
		}
		var protected strings.Builder
		source := f.Text
		if report.Source != nil {
			source = *report.Source
			if !f.AssistantText || !strings.HasPrefix(f.Text, source) {
				panic(errors.New("The privacy plugin returned invalid assistant history"))
			}
		}
		last := 0
		for _, change := range report.Changes {
			if change.Start < last || change.End <= change.Start || change.End > len(source) ||
				source[change.Start:change.End] != change.Value {
				panic(errors.New("The privacy plugin returned an invalid replacement range"))
			}
			protected.WriteString(source[last:change.Start])
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
		protected.WriteString(source[last:])
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
	if m.notice != nil {
		format := gjson.GetBytes(body, "response_format")
		m.chatNotice = gjson.GetBytes(body, "messages").IsArray() &&
			gjson.GetBytes(body, "n").Int() <= 1 &&
			(!format.Exists() || format.Raw == "null" || format.Get("type").String() == "text")
	}
	return out, hits
}

func (m *pluginMasker) TextHitsContext(ctx context.Context, text string) (string, []gwmw.Hit) {
	out, hits := m.protect(ctx, []redact.Fragment{{Text: text, Scope: "user"}})
	return out[0], hits
}

func (m *pluginMasker) JSONHits(body []byte) ([]byte, []gwmw.Hit) {
	return m.JSONHitsContext(m.ctx, body)
}
func (m *pluginMasker) TextHits(s string) (string, []gwmw.Hit) { return m.TextHitsContext(m.ctx, s) }
func (m *pluginMasker) JSON(b []byte) ([]byte, int)            { out, h := m.JSONHits(b); return out, len(h) }
func (m *pluginMasker) Text(s string) (string, int)            { out, h := m.TextHits(s); return out, len(h) }
func (m *pluginMasker) Value(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
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

func (m *pluginMasker) Writer(w http.ResponseWriter) (http.ResponseWriter, func()) {
	var notice func(map[string]int) string
	if m.chatNotice {
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
	writer := redact.NewRestoringWriter(w, m.restore, notice)
	return writer, writer.Finish
}

var _ gwmw.ContextTeller = (*pluginMasker)(nil)

func (m *pluginMasker) PrivacyName() string { return m.name }
