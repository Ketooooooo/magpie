package privacyengine

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/plugin"
)

type engineInput struct {
	Body  string   `json:"body,omitempty"`
	Texts []string `json:"texts,omitempty"`
}

type protectedInput struct {
	engineInput
	Hits    []gwmw.Hit
	Restore bool
}

type pluginMasker struct {
	ctx    context.Context
	name   string
	begin  func(context.Context, engineInput, *protectedInput) (*plugin.PrivacyStream, error)
	stream *plugin.PrivacyStream
}

func (m *pluginMasker) protect(ctx context.Context, in engineInput) protectedInput {
	var out protectedInput
	stream, err := m.begin(ctx, in, &out)
	if err != nil {
		panic(pluginUnavailable)
	}
	if (in.Body != "" && !json.Valid([]byte(out.Body))) || len(out.Texts) != len(in.Texts) {
		stream.Close()
		panic(pluginUnavailable)
	}
	m.Close()
	if out.Restore {
		m.stream = stream
	} else {
		stream.Close()
	}
	return out
}

func (m *pluginMasker) JSONHitsContext(ctx context.Context, body []byte) ([]byte, []gwmw.Hit) {
	out := m.protect(ctx, engineInput{Body: string(body)})
	return []byte(out.Body), out.Hits
}

func (m *pluginMasker) TextHitsContext(ctx context.Context, text string) (string, []gwmw.Hit) {
	out, hits := m.TextsHitsContext(ctx, []string{text})
	return out[0], hits
}

func (m *pluginMasker) TextsHitsContext(ctx context.Context, texts []string) ([]string, []gwmw.Hit) {
	out := m.protect(ctx, engineInput{Texts: texts})
	return out.Texts, out.Hits
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

func (m *pluginMasker) Restore(text string, _ bool) string {
	if m.stream == nil {
		return text
	}
	var out replyOutput
	if m.stream.Reply(replyInput{Data: []byte(text), ContentType: "text/plain", Finish: true}, &out) != nil {
		return text
	}
	return string(out.Data)
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
	writer := &pluginWriter{w: w, stream: m.stream, present: present, put: make(map[string]int)}
	return writer, func() { defer m.Close(); writer.finish() }
}

func (m *pluginMasker) Close() {
	if m.stream != nil {
		m.stream.Close()
		m.stream = nil
	}
}

var _ gwmw.ContextTeller = (*pluginMasker)(nil)

func (m *pluginMasker) PrivacyName() string { return m.name }
