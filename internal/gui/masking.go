package gui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/maskrec"
	"github.com/yetone/magpie/internal/privacyengine"
	"github.com/yetone/magpie/internal/settings"
)

// previewMax is how much text the preview masks.
const previewMax = 64 << 10

// valuesMax is how many placeholders one /api/masking/values asks for.
const valuesMax = 2000

// maskedRecord is a record as the page shows it: each value says whether
// the masker still knows what it stood for, so the page offers to show it
// only where it can.
type maskedRecord struct {
	maskrec.Record
	// Key is a string, as gateway.Masked's: a JS number rounds it
	Key     int64               `json:"key,string"`
	Values  []maskedValue       `json:"values,omitempty"`
	Actions []gwmw.RecordAction `json:"actions,omitempty"`
}

type maskedValue struct {
	maskrec.Value
	Known bool `json:"known,omitempty"`
}

func shownRecord(r maskrec.Record) maskedRecord {
	out := maskedRecord{Record: r, Key: r.Key}
	for _, action := range privacyengine.RecordActions(r) {
		action.TargetRef = ""
		out.Actions = append(out.Actions, action)
	}
	placeholders := make([]string, 0, len(r.Values))
	for _, v := range r.Values {
		placeholders = append(placeholders, v.Placeholder)
	}
	values := privacyengine.RecordValues(r, placeholders)
	for _, v := range r.Values {
		_, known := values[v.Placeholder]
		out.Values = append(out.Values, maskedValue{Value: v, Known: known})
	}
	return out
}

// maskingRoutes are Settings → Privacy's record of what masking swapped:
//   - GET /api/masking/summary?days= is maskrec.Sum;
//   - GET /api/masking/records?before=&limit=&kind=&by=&agent=&provider=&blocked=
//     a page of records, newest first (kind may list several, split by
//     commas; blocked=1 keeps the requests held back);
//   - GET /api/masking/record?key= one record;
//   - GET /api/masking/sent?key= the body a record's request went to its
//     vendor with, masked, while this magpie keeps it (the latest
//     maskrec keeps; 404 after a restart);
//   - POST /api/masking/values {recordKey, ps} what each placeholder stood for, of
//     those the masker still remembers, for the page to show the request
//     as the agent sent it;
//   - POST /api/masking/clear deletes every record kept (maskrec.Clear),
//     at once rather than after 30 days (maxyou2090 on Discord);
//   - POST /api/masking/preview {text} the text as a vendor would get it
//     under the settings now, and what was found, each told by its kind
//     and hint, never its value; nothing of it is remembered (#1977);
func maskingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/privacy-engine", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		if err := privacyengine.Select(r.Context(), in.ID); err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, settingsState())
	})

	mux.HandleFunc("POST /api/masking/record-action", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Key int64  `json:"recordKey,string"`
			ID  string `json:"actionId"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&in); err != nil || decoder.Decode(new(any)) != io.EOF || in.Key <= 0 || in.ID == "" {
			fail(rw, errors.New("Expected a masking record and an action ID"))
			return
		}
		if err := privacyengine.ApplyRecordAction(r.Context(), in.Key, in.ID); err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, settingsState())
	})

	mux.HandleFunc("POST /api/masking/preview", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4*previewMax)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		if len(in.Text) > previewMax {
			in.Text = strings.ToValidUTF8(in.Text[:previewMax], "")
		}
		st, err := settings.SharedChecked()
		if err != nil {
			fail(rw, err)
			return
		}
		text, hits, off, err := privacyengine.Preview(r.Context(), st, in.Text)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusServiceUnavailable)
			return
		}
		type hit struct {
			Kind        string `json:"kind"`
			By          string `json:"by"`
			Action      string `json:"action,omitempty"`
			Placeholder string `json:"placeholder"`
			Head        string `json:"head,omitempty"`
			Len         int    `json:"len"`
		}
		out := []hit{}
		for _, h := range hits {
			out = append(out, hit{h.Kind, h.By, h.Action, h.Placeholder, h.Head, h.Len})
		}
		writeJSON(rw, map[string]any{"text": text, "hits": out, "off": off})
	})
	mux.HandleFunc("POST /api/masking/clear", func(rw http.ResponseWriter, r *http.Request) {
		if err := maskrec.Clear(); err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, map[string]bool{"cleared": true})
	})
	mux.HandleFunc("GET /api/masking/summary", func(rw http.ResponseWriter, r *http.Request) {
		days, _ := strconv.Atoi(r.URL.Query().Get("days"))
		writeJSON(rw, maskrec.Sum(min(max(days, 1), 30)))
	})
	mux.HandleFunc("GET /api/masking/records", func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
		limit, _ := strconv.Atoi(q.Get("limit"))
		rs, more := maskrec.List(before, min(max(limit, 1), 200), maskrec.Filter{Kind: q.Get("kind"), By: q.Get("by"), Agent: q.Get("agent"), Provider: q.Get("provider"), Blocked: q.Get("blocked") == "1"})
		out := []maskedRecord{}
		for _, rec := range rs {
			out = append(out, shownRecord(rec))
		}
		writeJSON(rw, map[string]any{"records": out, "more": more})
	})
	mux.HandleFunc("GET /api/masking/record", func(rw http.ResponseWriter, r *http.Request) {
		key, _ := strconv.ParseInt(r.URL.Query().Get("key"), 10, 64)
		rec, ok := maskrec.Get(key)
		if !ok {
			http.NotFound(rw, r)
			return
		}
		writeJSON(rw, shownRecord(rec))
	})
	mux.HandleFunc("GET /api/masking/sent", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-store")
		key, _ := strconv.ParseInt(r.URL.Query().Get("key"), 10, 64)
		body, ok := maskrec.SentOf(key)
		if !ok {
			http.NotFound(rw, r)
			return
		}
		writeJSON(rw, map[string]string{"body": body})
	})
	mux.HandleFunc("POST /api/masking/values", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-store")
		var in struct {
			Key int64    `json:"recordKey,string"`
			Ps  []string `json:"ps"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		record, ok := maskrec.Get(in.Key)
		if !ok {
			http.NotFound(rw, r)
			return
		}
		writeJSON(rw, map[string]any{"values": privacyengine.RecordValues(record, in.Ps[:min(len(in.Ps), valuesMax)])})
	})
}
