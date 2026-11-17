// Package policy contains the saved rule format and irreversible log scrubbing
// used by Magpie outside the privacy engine. It cannot mask or restore a request.
package policy

import "github.com/yetone/magpie/internal/privacyengine/internal/redact"

type Rule = redact.Rule
type Found = redact.Found

func Categories() []redact.Category { return append([]redact.Category(nil), redact.Categories...) }

const (
	Warn     = redact.Warn
	Block    = redact.Block
	Scrubbed = redact.Scrubbed
)

func CheckRules(rules []Rule) ([]Rule, error) { return redact.CheckRules(rules) }
func KindName(kind string) bool               { return redact.KindName(kind) }

func Scrub(s string) string                 { return redact.Scrub(s) }
func ScrubJSON(body []byte) []byte          { return redact.ScrubJSON(body) }
func ScrubHeader(name, value string) string { return redact.ScrubHeader(name, value) }
func SecretName(name string) bool           { return redact.SecretName(name) }
