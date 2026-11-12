package privacyengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/lazyre"
	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/redact"
	"github.com/yetone/magpie/internal/settings"
	"github.com/yetone/magpie/internal/steady"
)

var companionUnavailable = errors.New("The privacy service is unavailable; nothing was sent")

var companionHTTP = &http.Client{
	Timeout:       10 * time.Second,
	Transport:     &http.Transport{MaxIdleConnsPerHost: 8},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type connection struct {
	Endpoint string             `json:"endpoint"`
	Token    string             `json:"token"`
	Spec     plugin.PrivacySpec `json:"spec"`
}

type companion struct {
	spec       plugin.PrivacySpec
	file       string
	conn       connection
	configured bool
}

func companionEngine(entry plugin.Entry, spec plugin.PrivacySpec) engine {
	hash := sha256.Sum256([]byte(entry.Spec + "\x00" + spec.ID))
	c := companion{
		spec: spec,
		file: filepath.Join(settings.Dir(), "privacy-engines", hex.EncodeToString(hash[:])+".json"),
	}
	if raw, err := os.ReadFile(c.file); err == nil &&
		json.Unmarshal(raw, &c.conn) == nil && sameService(c.conn.Spec, spec) && validConnection(c.conn) {
		c.configured = true
	} else {
		c.conn = connection{}
	}
	return engine{
		info:     Info{ID: spec.ID, Name: spec.Name, Configured: c.configured, Endpoint: c.conn.Endpoint, Off: entry.Off},
		check:    c.check,
		validate: compatible,
		begin: func(ctx context.Context, _ settings.Settings, _ bool) (context.Context, gwmw.Masker, error) {
			if !c.configured {
				return ctx, nil, errors.New("Configure this privacy plugin before using it")
			}
			return ctx, c.masker(ctx), nil
		},
		preview: c.preview,
		remote:  &c,
	}
}

// Bind consent and credentials to the declared wire service. Renaming the
// plugin for display does not invalidate its connection.
func sameService(a, b plugin.PrivacySpec) bool {
	a.Name, b.Name = "", ""
	return a == b
}

func compatible(st settings.Settings) error {
	if st.RedactRouteTo != "" || len(st.RedactActions) != 0 || len(st.RedactAllow) != 0 ||
		len(st.RedactWords) != 0 || len(st.RedactRules) != 0 {
		return errors.New("This privacy plugin cannot use the current Magpie custom masking rules, exceptions, actions or alternate route")
	}
	return nil
}

func validConnection(c connection) bool {
	base, err := url.Parse(c.Endpoint)
	return err == nil && base.Scheme == "http" && base.User == nil && base.Fragment == "" &&
		base.RawQuery == "" && (base.Path == "" || base.Path == "/") && base.RawPath == "" &&
		net.ParseIP(base.Hostname()).IsLoopback() && len(c.Token) >= 32 && len(c.Token) <= 4096 &&
		!strings.ContainsAny(c.Token, "\r\n")
}

func (c companion) configure(ctx context.Context, endpoint, token string) error {
	endpoint, token = strings.TrimRight(strings.TrimSpace(endpoint), "/"), strings.TrimSpace(token)
	if token == "" && c.configured && endpoint == c.conn.Endpoint {
		token = c.conn.Token
	}
	c.conn = connection{Endpoint: endpoint, Token: token, Spec: c.spec}
	if !validConnection(c.conn) {
		return errors.New("Enter a numeric loopback HTTP address and a service token of at least 32 characters")
	}
	c.configured = true
	if err := c.check(ctx); err != nil {
		return err
	}
	raw, err := json.Marshal(c.conn)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.file), 0o700); err != nil {
		return err
	}
	return steady.WriteFile(c.file, raw, 0o600)
}

func (c companion) check(ctx context.Context) error {
	if !c.configured {
		return errors.New("Configure this privacy plugin before using it")
	}
	_, _, _, err := c.preview(ctx, "Magpie privacy connection test.")
	return err
}

func (c companion) version(ctx context.Context) (uint64, error) {
	if !c.configured {
		return 0, errors.New("Configure this privacy plugin before using it")
	}
	var state struct {
		Version *uint64 `json:"active_version"`
	}
	err := c.call(ctx, http.MethodGet, c.spec.StatePath, nil, &state)
	if err != nil {
		return 0, err
	}
	if state.Version == nil {
		return 0, companionUnavailable
	}
	return *state.Version, nil
}

func (c companion) call(ctx context.Context, method, path string, input any, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return companionUnavailable
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.conn.Endpoint+path, body)
	if err != nil {
		return companionUnavailable
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(c.spec.TokenHeader, c.conn.Token)
	res, err := companionHTTP.Do(req)
	if err != nil {
		return companionUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return companionUnavailable
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, 4<<20))
	if err := dec.Decode(output); err != nil || dec.Decode(new(any)) != io.EOF {
		return companionUnavailable
	}
	return nil
}

func (c companion) preview(ctx context.Context, input string) (string, []gwmw.Hit, bool, error) {
	type result struct {
		text string
		hits []gwmw.Hit
	}
	m := c.masker(ctx)
	out, err := gwmw.Safely(func() result {
		text, hits := m.TextHitsContext(ctx, input)
		return result{text, hits}
	})
	return out.text, out.hits, false, err
}

type companionMasker struct {
	service companion
	mu      sync.Mutex
	ctx     context.Context
	values  map[string]string
	version *uint64
	reports map[redact.Fragment]scanReport
}

func (c companion) masker(ctx context.Context) *companionMasker {
	return &companionMasker{service: c, ctx: ctx, values: map[string]string{}, reports: map[redact.Fragment]scanReport{}}
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

func (m *companionMasker) protect(ctx context.Context, fragments []redact.Fragment) ([]string, []gwmw.Hit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if m.version == nil {
		version, err := m.service.version(ctx)
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
			if err := m.service.call(ctx, http.MethodPost, m.service.spec.ScanPath, input, &report); err != nil {
				panic(err)
			}
			m.reports[f] = report
		}
		if !report.Complete {
			panic(companionUnavailable)
		}
		var protected strings.Builder
		last := 0
		for _, change := range report.Changes {
			if change.Start < last || change.End <= change.Start || change.End > len(f.Text) ||
				f.Text[change.Start:change.End] != change.Value {
				panic(companionUnavailable)
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
			panic(companionUnavailable)
		}
		texts = append(texts, report.Protected)
	}
	return texts, hits
}

func (m *companionMasker) JSONHitsContext(ctx context.Context, body []byte) ([]byte, []gwmw.Hit) {
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

func (m *companionMasker) TextHitsContext(ctx context.Context, text string) (string, []gwmw.Hit) {
	out, hits := m.protect(ctx, []redact.Fragment{{Text: text, Scope: "user"}})
	return out[0], hits
}

func (m *companionMasker) JSONHits(body []byte) ([]byte, []gwmw.Hit) {
	return m.JSONHitsContext(m.ctx, body)
}
func (m *companionMasker) TextHits(s string) (string, []gwmw.Hit) { return m.TextHitsContext(m.ctx, s) }
func (m *companionMasker) JSON(b []byte) ([]byte, int)            { out, h := m.JSONHits(b); return out, len(h) }
func (m *companionMasker) Text(s string) (string, int)            { out, h := m.TextHits(s); return out, len(h) }
func (m *companionMasker) Value(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[token]
	return v, ok
}

func (m *companionMasker) Restore(text string, escaped bool) string {
	return m.restore(text, escaped, nil)
}

func (m *companionMasker) restore(text string, escaped bool, put map[string]int) string {
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

func (m *companionMasker) Writer(w http.ResponseWriter) (http.ResponseWriter, func()) {
	writer := redact.NewRestoringWriter(w, m.restore)
	return writer, writer.Finish
}

var _ gwmw.ContextTeller = (*companionMasker)(nil)

func (m *companionMasker) PrivacyName() string { return m.service.spec.Name }
