package privacyengine

import (
	"cmp"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/maskrec"
)

func builtinRecordValue(p string) (string, bool) {
	m, _ := servedBuiltin()
	if teller, ok := m.(gwmw.Teller); ok {
		return teller.Value(p)
	}
	return "", false
}

// RecordValues resolves only placeholders recorded by the originating engine.
// Engines with request-local restoration do not retain values for history.
func RecordValues(record maskrec.Record, placeholders []string) map[string]string {
	out := map[string]string{}
	e, err := lookup(cmp.Or(record.Engine, Builtin))
	if err != nil || e.recordValue == nil {
		return out
	}
	known := make(map[string]bool, len(record.Values))
	for _, value := range record.Values {
		if value.Action != "warn" {
			known[value.Placeholder] = true
		}
	}
	for _, p := range placeholders {
		if !known[p] {
			continue
		}
		if value, ok := e.recordValue(p); ok {
			out[p] = value
		}
	}
	return out
}
