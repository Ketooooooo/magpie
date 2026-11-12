package privacyengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/lazyre"
	"github.com/yetone/magpie/internal/redact"
	"github.com/yetone/magpie/internal/settings"
)

var grayUnavailable = errors.New("Gray Privacy is unavailable; nothing was sent")

var grayHTTP = &http.Client{
	Timeout:       10 * time.Second,
	Transport:     &http.Transport{MaxIdleConnsPerHost: 8},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func compatible(st settings.Settings) error {
	if st.RedactRouteTo != "" || len(st.RedactActions) != 0 || len(st.RedactAllow) != 0 ||
		len(st.RedactWords) != 0 || len(st.RedactRules) != 0 {
		return errors.New("Gray Privacy cannot use the current Magpie custom masking rules, exceptions, actions or alternate route")
	}
	return nil
}

func checkGray(ctx context.Context) error {
	_, err := grayVersion(ctx)
	return err
}

func grayVersion(ctx context.Context) (uint64, error) {
	var state struct {
		Version *uint64 `json:"active_version"`
	}
	err := grayCall(ctx, http.MethodGet, "state", nil, &state)
	if err != nil {
		return 0, err
	}
	if state.Version == nil {
		return 0, grayUnavailable
	}
	return *state.Version, nil
}

func grayCall(ctx context.Context, method, path string, input any, output any) error {
	base, err := url.Parse(os.Getenv("MAGPIE_GRAY_PRIVACY_URL"))
	token := os.Getenv("MAGPIE_GRAY_PRIVACY_TOKEN")
	if err != nil || base.Scheme != "http" || base.User != nil || base.Fragment != "" ||
		base.RawQuery != "" || !net.ParseIP(base.Hostname()).IsLoopback() || len(token) < 32 {
		return errors.New("Configure a local Gray Privacy service before selecting Gray Privacy")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return grayUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, method, base.JoinPath("api/v1/privacy", path).String(), bytes.NewReader(raw))
	if err != nil {
		return grayUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gray-Host-Token", token)
	res, err := grayHTTP.Do(req)
	if err != nil {
		return grayUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return grayUnavailable
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, 4<<20))
	if err := dec.Decode(output); err != nil || dec.Decode(new(any)) != io.EOF {
		return grayUnavailable
	}
	return nil
}

type grayMasker struct {
	mu      sync.Mutex
	ctx     context.Context
	values  map[string]string
	version *uint64
	reports map[redact.Fragment]grayReport
}

func newGray(ctx context.Context) gwmw.Masker {
	return &grayMasker{ctx: ctx, values: map[string]string{}, reports: map[redact.Fragment]grayReport{}}
}

type grayReport struct {
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

func (m *grayMasker) protect(ctx context.Context, fragments []redact.Fragment) ([]string, []gwmw.Hit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if m.version == nil {
		version, err := grayVersion(ctx)
		if err != nil {
			panic(err)
		}
		m.version = &version
	}
	var hits []gwmw.Hit
	texts := make([]string, 0, len(fragments))
	for _, f := range fragments {
		if f.Text == "" {
			texts = append(texts, "")
			continue
		}
		report, found := m.reports[f]
		if !found {
			input := map[string]any{"text": f.Text, "scope": f.Scope, "version": "active", "expected_version": *m.version}
			if err := grayCall(ctx, http.MethodPost, "scan", input, &report); err != nil {
				panic(err)
			}
			m.reports[f] = report
		}
		if !report.Complete {
			panic(grayUnavailable)
		}
		var protected strings.Builder
		last := 0
		for _, change := range report.Changes {
			if change.Start < last || change.End <= change.Start || change.End > len(f.Text) ||
				f.Text[change.Start:change.End] != change.Value {
				panic(grayUnavailable)
			}
			protected.WriteString(f.Text[last:change.Start])
			protected.WriteString(change.Mask)
			last = change.End
			if change.Reversible {
				if change.Mask == "" || maskToken.FindString(change.Mask) != change.Mask {
					panic(errors.New("Gray Privacy returned an unsupported reversible mask"))
				}
				if value, found := m.values[change.Mask]; found && value != change.Value {
					panic(errors.New("Gray Privacy returned a conflicting mask"))
				}
				m.values[change.Mask] = change.Value
			}
			hits = append(hits, gwmw.Hit{Kind: change.Category, By: "rule", Placeholder: change.Mask})
		}
		protected.WriteString(f.Text[last:])
		if protected.String() != report.Protected {
			panic(grayUnavailable)
		}
		texts = append(texts, report.Protected)
	}
	return texts, hits
}

func (m *grayMasker) JSONHitsContext(ctx context.Context, body []byte) ([]byte, []gwmw.Hit) {
	var hits []gwmw.Hit
	out, ok := redact.MapFragments(body, func(fragments []redact.Fragment) []string {
		var texts []string
		texts, hits = m.protect(ctx, fragments)
		return texts
	})
	if !ok {
		panic(errors.New("Gray Privacy could not read the request"))
	}
	return out, hits
}

func (m *grayMasker) TextHitsContext(ctx context.Context, text string) (string, []gwmw.Hit) {
	out, hits := m.protect(ctx, []redact.Fragment{{Text: text, Scope: "user"}})
	return out[0], hits
}

func (m *grayMasker) JSONHits(body []byte) ([]byte, []gwmw.Hit) {
	return m.JSONHitsContext(m.ctx, body)
}
func (m *grayMasker) TextHits(s string) (string, []gwmw.Hit) { return m.TextHitsContext(m.ctx, s) }
func (m *grayMasker) JSON(b []byte) ([]byte, int)            { out, h := m.JSONHits(b); return out, len(h) }
func (m *grayMasker) Text(s string) (string, int)            { out, h := m.TextHits(s); return out, len(h) }
func (m *grayMasker) Value(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[token]
	return v, ok
}

func (m *grayMasker) Restore(text string, escaped bool) string {
	return m.restore(text, escaped, nil)
}

func (m *grayMasker) restore(text string, escaped bool, put map[string]int) string {
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

func (m *grayMasker) Writer(w http.ResponseWriter) (http.ResponseWriter, func()) {
	writer := redact.NewRestoringWriter(w, m.restore)
	return writer, writer.Finish
}

var _ gwmw.ContextTeller = (*grayMasker)(nil)
