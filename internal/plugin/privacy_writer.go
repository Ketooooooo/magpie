package plugin

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
)

type replyInput struct {
	Data        []byte `json:"data,omitempty"`
	ContentType string `json:"contentType"`
	Present     bool   `json:"present,omitempty"`
	Finish      bool   `json:"finish,omitempty"`
}

type replyOutput struct {
	Data []byte
	Put  map[string]int
}

// pluginWriter carries opaque response bytes to the same plugin session
// that protected the request. The plugin owns the response format.
type pluginWriter struct {
	w                                http.ResponseWriter
	stream                           *privacyStream
	present, bypass, started, failed bool
	contentType                      string
	put                              map[string]int
}

func (w *pluginWriter) Header() http.Header         { return w.w.Header() }
func (w *pluginWriter) Unwrap() http.ResponseWriter { return w.w }
func (w *pluginWriter) Put() map[string]int         { return w.put }

func (w *pluginWriter) WriteHeader(code int) {
	if code >= 200 && !w.started {
		w.start(code)
	}
	w.w.WriteHeader(code)
}

func (w *pluginWriter) start(status int) {
	w.started = true
	w.contentType = w.Header().Get("Content-Type")
	encoding := w.Header().Get("Content-Encoding")
	content := strings.ToLower(w.contentType)
	w.bypass = status >= 300 || encoding != "" && !strings.EqualFold(encoding, "identity") ||
		content != "" && !strings.HasPrefix(content, "text/") && !strings.Contains(content, "json") && !strings.Contains(content, "event-stream")
	if !w.bypass {
		w.Header().Del("Content-Length")
	}
}

func (w *pluginWriter) Write(data []byte) (int, error) {
	if !w.started {
		w.start(http.StatusOK)
	}
	if w.bypass {
		return w.w.Write(data)
	}
	if w.contentType == "" && (bytes.HasPrefix(data, []byte("data:")) || bytes.HasPrefix(data, []byte("event:")) || bytes.HasPrefix(data, []byte(":"))) {
		w.contentType = "text/event-stream"
	}
	return len(data), w.transform(data, false)
}

func (w *pluginWriter) Flush() {
	if w.bypass || strings.Contains(w.contentType, "event-stream") {
		_ = http.NewResponseController(w.w).Flush()
	}
}

func (w *pluginWriter) finish() {
	if w.started && !w.bypass && !w.failed {
		_ = w.transform(nil, true)
		w.Flush()
	}
}

func (w *pluginWriter) transform(data []byte, finish bool) error {
	if w.failed {
		return errReplyProtection
	}
	var out replyOutput
	if err := w.stream.Reply(replyInput{Data: data, ContentType: w.contentType, Present: w.present, Finish: finish}, &out); err != nil {
		w.failed = true
		if strings.Contains(w.contentType, "event-stream") {
			_, _ = w.w.Write([]byte("data: " + replyProtectionError + "\n\n"))
			w.Flush()
		} else {
			_, _ = w.w.Write([]byte(replyProtectionError))
		}
		return errReplyProtection
	}
	for mask, n := range out.Put {
		w.put[mask] += n
	}
	if len(out.Data) > 0 {
		_, err := w.w.Write(out.Data)
		return err
	}
	return nil
}

const replyProtectionError = `{"error":{"message":"The privacy engine could not restore the reply"}}`

var errReplyProtection = errors.New("the privacy engine could not restore the reply")
