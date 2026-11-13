package privacyengine

import (
	"context"
	"net/http"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/redact"
)

type protectedFields struct {
	Texts   []string
	Hits    []gwmw.Hit
	Restore bool
}

type pluginMasker struct {
	ctx         context.Context
	name        string
	begin       func(context.Context, []redact.Fragment, any) (*plugin.PrivacyStream, error)
	stream      *plugin.PrivacyStream
	replyNotice bool
}

func (m *pluginMasker) protect(ctx context.Context, fragments []redact.Fragment) ([]string, []gwmw.Hit) {
	if len(fragments) == 0 {
		return nil, nil
	}
	var out protectedFields
	stream, err := m.begin(ctx, fragments, &out)
	if err != nil {
		panic(pluginUnavailable)
	}
	if len(out.Texts) != len(fragments) {
		stream.Close()
		panic(pluginUnavailable)
	}
	if out.Restore {
		m.stream = stream
	} else {
		stream.Close()
	}
	return out.Texts, out.Hits
}

func (m *pluginMasker) JSONHitsContext(ctx context.Context, body []byte) ([]byte, []gwmw.Hit) {
	var hits []gwmw.Hit
	out, ok := redact.MapFragments(body, func(fragments []redact.Fragment) []string {
		var texts []string
		texts, hits = m.protect(ctx, fragments)
		return texts
	})
	if !ok {
		panic(pluginUnavailable)
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
func (m *pluginMasker) JSON(b []byte) ([]byte, int) {
	out, hits := m.JSONHits(b)
	return out, len(hits)
}
func (m *pluginMasker) Text(s string) (string, int) {
	out, hits := m.TextHits(s)
	return out, len(hits)
}
func (m *pluginMasker) Value(string) (string, bool) { return "", false }

func (m *pluginMasker) Restore(text string, arguments bool) string {
	if m.stream == nil {
		return text
	}
	out, err := redact.RestoreMessage(m.stream.Reply, text, arguments)
	if err != nil {
		return text
	}
	return out
}

func (m *pluginMasker) Writer(w http.ResponseWriter) (http.ResponseWriter, func()) {
	return m.replyWriter(w, false)
}
func (m *pluginMasker) WriterWithNotice(w http.ResponseWriter) (http.ResponseWriter, func()) {
	return m.replyWriter(w, true)
}

func (m *pluginMasker) replyWriter(w http.ResponseWriter, present bool) (http.ResponseWriter, func()) {
	if m.stream == nil {
		return w, func() {}
	}
	stream := m.stream
	writer := redact.NewMessageWriter(w, stream.Reply, present && m.replyNotice)
	return writer, func() { defer stream.Close(); writer.Finish() }
}

func (m *pluginMasker) Close() {
	if m.stream != nil {
		m.stream.Close()
	}
}

var _ gwmw.ContextTeller = (*pluginMasker)(nil)

func (m *pluginMasker) PrivacyName() string { return m.name }
