// Package responsesstream holds Responses event rules shared by the relay,
// protocol translation, and message rewriting.
package responsesstream

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// PickArgs returns the fuller of a call's streamed arguments and its done
// snapshot, preferring valid JSON.
func PickArgs(streamed, done string) string {
	s, f := strings.TrimSpace(streamed), strings.TrimSpace(done)
	switch sv, fv := json.Valid([]byte(s)), json.Valid([]byte(f)); {
	case fv && (!sv || len(f) > len(s)):
		return done
	case sv || f == "":
		return streamed
	default:
		return done
	}
}

// CallKey identifies a Responses tool call by its item ID, or by its output
// index when the stream does not name the item.
func CallKey(itemID, outputIndex string) string {
	if itemID != "" {
		return itemID
	}
	return "#" + outputIndex
}

// Numbering keeps events in increasing sequence after a transform inserts or
// moves an event. It preserves numbers that are already ahead.
type Numbering struct {
	last int64
	seen bool
}

func (n *Numbering) Next() int64 {
	if !n.seen {
		return 0
	}
	return n.last + 1
}

// Number returns the adjusted JSON payload, or nil when it needs no edit.
func (n *Numbering) Number(data []byte) []byte {
	seq := gjson.GetBytes(data, "sequence_number")
	if seq.Type != gjson.Number || seq.Index <= 0 {
		return nil
	}
	number := seq.Int()
	next := n.Next()
	if n.seen && number < next {
		n.last = next
		out := append([]byte(nil), data[:seq.Index]...)
		out = strconv.AppendInt(out, next, 10)
		return append(out, data[seq.Index+len(seq.Raw):]...)
	}
	n.last, n.seen = number, true
	return nil
}
