package redact

import (
	"strings"

	"github.com/tidwall/gjson"
)

// Fragment is a text field an engine may change without altering protocol structure.
type Fragment struct {
	Text  string
	Scope string
}

// MapFragments lets a batch engine use the same exclusions as built-in masking.
func MapFragments(body []byte, transform func([]Fragment) []string) ([]byte, bool) {
	signed, args, defs := scan(body)
	eligible := func(path, key, text string) bool {
		return !under(path, signed) && !keepIn(path, key, text, args, defs)
	}
	var fragments []Fragment
	if _, ok := walk(body, func(path, key, text string) string {
		if !eligible(path, key, text) {
			return text
		}
		scope := "user"
		switch {
		case under(path, defs):
			scope = "tool_definition"
		case under(path, args) || key == "arguments":
			scope = "tool"
		case path == "/system" || strings.HasPrefix(path, "/system/") || path == "/instructions":
			scope = "system"
		default:
			parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
			if len(parts) == 3 && (parts[0] == "messages" || parts[0] == "input" || parts[0] == "contents") {
				role := gjson.GetBytes(body, parts[0]+"."+parts[1]+".role").String()
				switch role {
				case "system", "developer":
					scope = "system"
				case "tool", "function":
					scope = "tool"
				}
			}
		}
		fragments = append(fragments, Fragment{text, scope})
		return text
	}); !ok {
		return nil, false
	}
	texts := transform(fragments)
	if len(texts) != len(fragments) {
		return nil, false
	}
	at := 0
	return walk(body, func(path, key, text string) string {
		if !eligible(path, key, text) {
			return text
		}
		out := texts[at]
		at++
		return out
	})
}
