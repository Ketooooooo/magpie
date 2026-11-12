package redact

import (
	"strings"

	"github.com/tidwall/gjson"
)

// Fragment is a text field an engine may change without altering protocol structure.
type Fragment struct {
	Text          string `json:"text"`
	Scope         string `json:"scope"`
	AssistantText bool   `json:"assistant_text,omitempty"`
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
		assistantText := false
		parts := strings.SplitN(path, ".", 4)
		switch {
		case under(path, defs):
			scope = "tool_definition"
		case under(path, args) || key == "arguments":
			scope = "tool"
		case parts[0] == "system" || path == "instructions":
			scope = "system"
		default:
			if len(parts) >= 3 && (parts[0] == "messages" || parts[0] == "input" || parts[0] == "contents") {
				item := parts[0] + "." + parts[1]
				role := gjson.GetBytes(body, item+".role").String()
				switch role {
				case "system", "developer":
					scope = "system"
				case "tool", "function":
					scope = "tool"
				case "assistant":
					if parts[0] == "messages" && parts[2] == "content" {
						assistantText = len(parts) == 3
						if len(parts) == 4 {
							index, field, ok := strings.Cut(parts[3], ".")
							assistantText = ok && field == "text" &&
								gjson.GetBytes(body, item+".content."+index+".type").String() == "text"
						}
					}
				}
			}
		}
		fragments = append(fragments, Fragment{Text: text, Scope: scope, AssistantText: assistantText})
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
