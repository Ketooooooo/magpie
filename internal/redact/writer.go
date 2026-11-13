package redact

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
)

// Writer puts the values back in what a vendor answers, on its way to the
// agent. A stream is put back event by event, as it comes; anything else
// when it is done, at Finish.
//
// A placeholder a stream splits between two events — {{API_ in one text
// delta, KEY_k3v9x2mq}} in the next — is put back whole: an event whose
// text ends in what may be the start of one is held until the next, and if
// that one goes on with the same text the start moves over to it. Nothing
// is added or dropped, so the text the agent puts together is the same.
type Writer struct {
	w       http.ResponseWriter
	mode    int // 0 not yet known, 1 a stream, 2 a whole body, 3 left as it is
	buf     bytes.Buffer
	pending *held
	done    bool
	replace restoreText
	tail    func(string, bool) int
	put     map[string]int // placeholders put back, each place counted
	notice  *chatNotice
	quotes  map[string]argumentQuote
}

const (
	unknown = iota
	stream
	whole
	asIs
)

// held is an event one or more of whose texts ended in what may be the
// start of a placeholder: each one's tail by its path.
type held struct {
	ctx       string
	tails     map[string]string
	args      map[string]string
	full, cut []byte // built-in's full event, and the event without the tails
}

// NewWriter wraps w; Finish must be called when the handler is done.
func NewWriter(w http.ResponseWriter) *Writer {
	return &Writer{w: w, tail: func(text string, _ bool) int { return partialTail(text) }}
}

// NewRestoringWriter frames replies for a request-bound engine.
func NewRestoringWriter(w http.ResponseWriter, replace restoreText, tail func(string, bool) int, renderNotice func(map[string]int) string) *Writer {
	rw := &Writer{w: w, replace: replace, tail: tail}
	if renderNotice != nil {
		rw.notice = &chatNotice{render: renderNotice}
	}
	return rw
}

func (rw *Writer) restore(text string, escaped bool, put map[string]int) string {
	if rw.replace != nil {
		return rw.replace(text, escaped, put)
	}
	return restore(text, escaped, put)
}

func (rw *Writer) Header() http.Header { return rw.w.Header() }

// Put is how many places of each placeholder the answer had put back,
// so far: for the record of what masking did.
func (rw *Writer) Put() map[string]int { return rw.put }

func (rw *Writer) count() map[string]int {
	if rw.put == nil {
		rw.put = map[string]int{}
	}
	return rw.put
}

// Unwrap is for http.ResponseController.
func (rw *Writer) Unwrap() http.ResponseWriter { return rw.w }

func (rw *Writer) decide(first []byte) {
	h := rw.w.Header()
	ct := h.Get("Content-Type")
	switch {
	case h.Get("Content-Encoding") != "" && !strings.EqualFold(h.Get("Content-Encoding"), "identity"):
		rw.mode = asIs
	case strings.Contains(ct, "event-stream"):
		rw.mode = stream
	case ct == "" && (bytes.HasPrefix(first, []byte("event:")) || bytes.HasPrefix(first, []byte("data:")) || bytes.HasPrefix(first, []byte(":"))):
		rw.mode = stream // the ChatGPT backend streams without saying so
	case binaryType(ct):
		rw.mode = asIs // speech, an image, a video: no text to put back
	default:
		rw.mode = whole
	}
}

// binaryType says a Content-Type is of bytes that aren't text: audio, an
// image, a video, a file. Held whole, speech played only when it ended.
func binaryType(ct string) bool {
	ct = strings.ToLower(ct)
	for _, t := range []string{"audio/", "image/", "video/", "application/octet-stream", "application/pdf", "application/zip"} {
		if strings.HasPrefix(ct, t) {
			return true
		}
	}
	return false
}

func (rw *Writer) WriteHeader(code int) {
	if code >= 300 {
		rw.notice = nil
	}
	if rw.mode == unknown {
		h := rw.w.Header()
		if ct := h.Get("Content-Type"); ct != "" {
			rw.decide(nil)
		}
		// what is put back is not as long as what came
		if rw.mode != asIs {
			h.Del("Content-Length")
		}
	}
	rw.w.WriteHeader(code)
}

func (rw *Writer) Write(p []byte) (int, error) {
	if rw.mode == unknown {
		rw.decide(p)
		if rw.mode != asIs {
			rw.w.Header().Del("Content-Length")
		}
	}
	switch rw.mode {
	case asIs:
		return rw.w.Write(p)
	case whole:
		return rw.buf.Write(p)
	}
	rw.buf.Write(p)
	for {
		b := rw.buf.Bytes()
		// a comment between two events (": keepalive") goes on as it
		// comes: held for the event after it, an agent behind a proxy
		// heard nothing while its vendor reasoned silently, and the
		// proxy hung up (#2402). It carries nothing to put back, and an
		// event held for its placeholder's tail goes on after it as well.
		if c := commentLines(b); c > 0 {
			if _, err := rw.w.Write(b[:c]); err != nil {
				return len(p), err
			}
			rw.buf.Next(c)
			continue
		}
		i, n := eventEnd(b)
		if i < 0 {
			break
		}
		ev := append([]byte(nil), b[:i+n]...)
		rw.buf.Next(i + n)
		if err := rw.event(ev); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// commentLines is how long the whole comment lines (": keepalive") and
// blank lines at the start of b are: b starts where an event does, so none
// of them is part of one.
func commentLines(b []byte) int {
	n := 0
	for n < len(b) && (b[n] == ':' || b[n] == '\n' || b[n] == '\r') {
		i := bytes.IndexByte(b[n:], '\n')
		if i < 0 || b[n] == '\r' && i != 1 {
			break
		}
		n += i + 1
	}
	return n
}

// eventEnd is where the first complete event in b ends, and the length of
// the blank line that ends it.
func eventEnd(b []byte) (int, int) {
	i := bytes.Index(b, []byte("\n\n"))
	j := bytes.Index(b, []byte("\r\n\r\n"))
	switch {
	case i < 0 && j < 0:
		return -1, 0
	case j >= 0 && (i < 0 || j < i):
		return j, 4
	default:
		return i, 2
	}
}

func (rw *Writer) Flush() {
	if f, ok := rw.w.(http.Flusher); ok && rw.mode != whole {
		f.Flush()
	}
}

// Finish writes what is still held.
func (rw *Writer) Finish() {
	if rw.done {
		return
	}
	rw.done = true
	switch rw.mode {
	case whole:
		mediaType, _, _ := strings.Cut(rw.Header().Get("Content-Type"), ";")
		if rw.replace != nil && strings.EqualFold(strings.TrimSpace(mediaType), "text/plain") &&
			!json.Valid(rw.buf.Bytes()) {
			rw.w.Write([]byte(rw.restore(rw.buf.String(), false, rw.count())))
		} else {
			rw.w.Write(restoreJSON(rw.buf.Bytes(), rw.count(), rw.replace, rw.notice))
		}
	case stream:
		_ = rw.release()
		if rw.buf.Len() > 0 {
			if rw.replace == nil {
				rw.w.Write([]byte(rw.restore(rw.buf.String(), false, rw.count())))
			} else {
				rw.w.Write(rw.buf.Bytes())
			}
		}
	}
	rw.Flush()
}

// event puts the values back in one event and writes it, or holds it.
//
// Every text of it is put back but what a vendor sealed (a signature, a
// file's data): a tool's own arguments, as Gemini streams them whole, use
// the keys a vendor uses for itself (name, type, id, url, status), and a
// name the model wrote under "name" kept its placeholder. Only a text is
// held for its tail, never an id or Responses' random obfuscation, and
// each text's tail is held for itself: obfuscation that ended in a kind's
// first letters took the hold from the delta beside it, and the next
// event's half of that placeholder went out as it came.
func (rw *Writer) event(ev []byte) error {
	if rw.pending == nil && rw.replace == nil && !holding() {
		_, err := rw.w.Write(ev) // nothing masked to put back
		return err
	}
	name, data, pre, post, ok := splitEvent(ev)
	if !ok {
		if err := rw.release(); err != nil {
			return err
		}
		if rw.replace != nil {
			_, err := rw.w.Write(ev)
			return err
		}
		_, err := rw.w.Write([]byte(rw.restore(string(ev), false, rw.count())))
		return err
	}
	if rw.pending != nil && waiting(name, data) {
		// a keepalive between two pieces of a text goes on ahead of the
		// piece held: released for it, the held piece went out with the
		// start of its placeholder as it was, the next piece with the
		// rest, and neither was a placeholder to put back (#5287)
		_, err := rw.w.Write(rebuild(pre, restoreJSON(data, rw.count(), rw.replace, nil), post))
		return err
	}
	ctx := name + "|" + eventCtx(data)
	// the starts of placeholders the last event ended in go on here
	var carry map[string]string
	if p := rw.pending; p != nil {
		if p.ctx == ctx && hasPaths(data, p.tails) && sameStreamArguments(data, name, p.args) {
			if _, err := rw.w.Write(p.cut); err != nil {
				return err
			}
			carry = p.tails
		} else if err := rw.release(); err != nil {
			return err
		}
		rw.pending = nil
	}
	typ := typeOf(data)
	if typ == "" {
		typ = name
	}
	var signed, args []string
	protocol := false
	if rw.replace != nil {
		signed, args, _ = scan(data)
		protocol = replyEnvelope(data, typ)
	}
	choice := rw.notice.choice(data, "delta")
	finished := choice.Get("finish_reason").String() != ""
	var tails, cuts map[string]string
	var heldArgs map[string]string
	restored, valid := walk(data, func(path, key, s string) string {
		masked := s
		if c, ok := carry[path]; ok {
			s = c + s
		}
		if sealedText(key, s) || rw.replace != nil &&
			privateReplyField(path, key, typ, protocol, signed, args) {
			return s
		}
		escaped := asJSON(key, typ)
		if rw.replace != nil && escaped {
			identity := streamArgument(data, name, typ, path, key)
			state := rw.quotes[identity]
			var n int
			if identity != "" && rw.tail != nil {
				argumentStrings(s, state, func(start, end int, open bool) {
					if open {
						n = rw.tail(s[start:end], true)
					}
				})
			}
			if n > 0 {
				if tails == nil {
					tails = make(map[string]string)
				}
				tails[path] = s[len(s)-n:]
				s = s[:len(s)-n]
			}
			if identity != "" {
				next := argumentStrings(s, state, nil)
				if rw.quotes == nil {
					rw.quotes = make(map[string]argumentQuote)
				}
				rw.quotes[identity] = next
				if n > 0 {
					if heldArgs == nil {
						heldArgs = make(map[string]string)
					}
					heldArgs[path] = identity
				}
			}
			return editArgument(s, state, func(text string, _ bool) string {
				return rw.restore(text, true, rw.count())
			})
		}
		visibleText := path == chatDeltaText && choice.Exists()
		// the tail is looked for before anything is put back, so a
		// placeholder whose last brace is still to come isn't put back
		// without it and the brace left behind
		if rw.tail != nil && (!kept[key] || rw.replace != nil) && key != "obfuscation" &&
			(!visibleText || !finished) {
			if n := rw.tail(s, escaped); n > 0 {
				if tails == nil {
					tails = make(map[string]string)
				}
				tails[path] = s[len(s)-n:]
				if rw.replace == nil {
					if cuts == nil {
						cuts = make(map[string]string)
					}
					cuts[path] = rw.restore(s[:len(s)-n], escaped, nil)
				} else {
					s = s[:len(s)-n] // count held masks only when written
				}
			}
		}
		// counted here only: cut is s again without its tail, and
		// whichever of the two goes out, the places are these
		if visibleText {
			put := make(map[string]int)
			text := rw.restore(s, false, put)
			rw.notice.record(masked, text, put, rw.count())
			return text
		}
		return rw.restore(s, escaped, rw.count())
	})
	if valid && tails[chatDeltaText] == "" {
		restored = rw.notice.append(restored, choice, "delta")
	}
	full := rebuild(pre, restored, post)
	if tails == nil {
		_, err := rw.w.Write(full)
		return err
	}
	if rw.replace != nil {
		rw.pending = &held{ctx: ctx, tails: tails, args: heldArgs, cut: full}
		return nil
	}
	cutData, _ := walk(restored, func(path, _, s string) string {
		if c, ok := cuts[path]; ok {
			return c
		}
		return s
	})
	rw.pending = &held{ctx: ctx, tails: tails, full: full, cut: rebuild(pre, cutData, post)}
	return nil
}

// waitEvents are the events a stream sends while the model is slow, which
// say nothing of the answer: Anthropic's ping, which its API and magpie's
// encoder send in the middle of a tool call's arguments, Responses'
// keepalive, and response.in_progress and response.queued, magpie's
// keepalive on that protocol.
var waitEvents = []string{"ping", "keepalive", "response.in_progress", "response.queued"}

// waiting says an event of name with data is one of waitEvents.
func waiting(name string, data []byte) bool {
	typ := typeOf(data)
	if typ == "" {
		typ = name
	}
	return slices.Contains(waitEvents, typ)
}

// sealedText says a string of a vendor's answer goes on as it came: what the
// vendor sealed (signatureKeys) and a file's encoded data.
func sealedText(key, s string) bool {
	return slices.Contains(signatureKeys, key) || strings.HasPrefix(s, "data:") ||
		key == "data" && len(s) >= 64 && !strings.ContainsAny(s, " \n")
}

// holding says some value is masked, and may be put back.
func holding() bool {
	mu.RLock()
	defer mu.RUnlock()
	return len(values) > 0
}

func (rw *Writer) release() error {
	if p := rw.pending; p != nil {
		rw.pending = nil
		full := p.full
		if full == nil {
			name, data, pre, post, _ := splitEvent(p.cut)
			typ := typeOf(data)
			if typ == "" {
				typ = name
			}
			choice := rw.notice.choice(data, "delta")
			out, _ := walk(data, func(path, key, s string) string {
				tail, ok := p.tails[path]
				if !ok {
					return s
				}
				if path == chatDeltaText && choice.Exists() {
					put := make(map[string]int)
					text := rw.restore(tail, false, put)
					rw.notice.record("", text, put, rw.count())
					return s + text
				}
				if identity, ok := p.args[path]; ok {
					state := rw.quotes[identity]
					rw.quotes[identity] = argumentStrings(tail, state, nil)
					return s + editArgument(tail, state, func(text string, _ bool) string {
						return rw.restore(text, true, rw.count())
					})
				}
				return s + rw.restore(tail, asJSON(key, typ), rw.count())
			})
			full = rebuild(pre, out, post)
		}
		_, err := rw.w.Write(full)
		return err
	}
	return nil
}

// streamArgument keys each JSON argument stream by its protocol tool identity.
// A whole argument object has no stream identity and starts outside a string.
func streamArgument(data []byte, name, typ, path, key string) string {
	if key == "delta" && typ == "response.function_call_arguments.delta" {
		return "response/" + gjson.GetBytes(data, "item_id").String() + "/" + gjson.GetBytes(data, "output_index").String()
	}
	if key == "partial_json" && (name == "content_block_delta" || typ == "content_block_delta") {
		return "block/" + gjson.GetBytes(data, "index").String()
	}
	parts := strings.Split(path, ".")
	if len(parts) >= 4 && parts[0] == "choices" && parts[2] == "delta" && key == "arguments" {
		choice := strings.Join(parts[:2], ".")
		id := "chat/" + streamIndex(data, choice, parts[1])
		if len(parts) == 7 && parts[3] == "tool_calls" && parts[5] == "function" {
			return id + "/" + streamIndex(data, strings.Join(parts[:5], "."), parts[4])
		}
		if len(parts) == 5 && parts[3] == "function_call" {
			return id + "/legacy"
		}
	}
	return ""
}

func streamIndex(data []byte, path, fallback string) string {
	if index := gjson.GetBytes(data, path+".index"); index.Exists() {
		return index.String()
	}
	return fallback
}

func sameStreamArguments(data []byte, name string, args map[string]string) bool {
	if len(args) == 0 {
		return true
	}
	typ := typeOf(data)
	if typ == "" {
		typ = name
	}
	for path, identity := range args {
		key := path[strings.LastIndexByte(path, '.')+1:]
		if streamArgument(data, name, typ, path, key) != identity {
			return false
		}
	}
	return true
}

func rebuild(pre, data, post []byte) []byte {
	out := make([]byte, 0, len(pre)+len(data)+len(post))
	return append(append(append(out, pre...), data...), post...)
}

// splitEvent finds the one data line of an event that has JSON in it:
// what comes before the JSON, the JSON, and what comes after it.
func splitEvent(ev []byte) (name string, data, pre, post []byte, ok bool) {
	lines := bytes.SplitAfter(ev, []byte("\n"))
	at := -1
	off := 0
	for i, l := range lines {
		t := bytes.TrimRight(l, "\r\n")
		switch {
		case bytes.HasPrefix(t, []byte("event:")):
			name = strings.TrimSpace(string(t[6:]))
		case bytes.HasPrefix(t, []byte("data:")):
			if at >= 0 {
				return "", nil, nil, nil, false // data over more than one line
			}
			at = i
		}
		if at < 0 {
			off += len(l)
		}
	}
	if at < 0 {
		return "", nil, nil, nil, false
	}
	l := lines[at]
	t := bytes.TrimRight(l, "\r\n")
	start := 5
	if len(t) > 5 && t[5] == ' ' {
		start = 6
	}
	d := t[start:]
	if len(d) == 0 || d[0] != '{' && d[0] != '[' {
		return "", nil, nil, nil, false
	}
	return name, d, ev[:off+start], ev[off+len(t):], true
}

// eventCtx is what says which text an event goes on with.
func eventCtx(data []byte) string {
	var b strings.Builder
	walk(data, func(path, _, s string) string {
		switch path {
		case "type", "item_id":
			b.WriteString(path + "=" + s + ";")
		}
		return s
	})
	for _, k := range []string{`"index":`, `"output_index":`, `"content_index":`} {
		if i := bytes.Index(data, []byte(k)); i >= 0 {
			j := i + len(k)
			e := j
			for e < len(data) && (data[e] >= '0' && data[e] <= '9' || data[e] == ' ') {
				e++
			}
			b.WriteString(k + string(data[j:e]) + ";")
		}
	}
	return b.String()
}

// hasPaths says data has a string at each of the paths.
func hasPaths(data []byte, paths map[string]string) bool {
	found := 0
	walk(data, func(p, _, s string) string {
		if _, ok := paths[p]; ok {
			found++
		}
		return s
	})
	return found == len(paths)
}
