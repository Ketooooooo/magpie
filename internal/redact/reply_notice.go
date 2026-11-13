package redact

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/tidwall/gjson"
)

const (
	replyNoticeTarget    = "#magpie-privacy-notice"
	replyNoticeHeading   = "🔒 Magpie masked the following values before sending them to the model."
	replyNoticeListStart = "- ["
	replyNoticeLinkStart = "](" + replyNoticeTarget + ` "`
	replyNoticeLinkEnd   = `")`
)

// FormatReplyNotice shows restored originals as links with their masks as
// hover titles. The fixed local target identifies this display-only suffix.
func FormatReplyNotice(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	masks := make([]string, 0, len(values))
	for mask := range values {
		masks = append(masks, mask)
	}
	slices.Sort(masks)
	var out strings.Builder
	out.WriteString("\n\n" + replyNoticeHeading + "\n")
	for _, mask := range masks {
		out.WriteString("\n" + replyNoticeListStart)
		writeNoticeText(&out, values[mask], false)
		out.WriteString(replyNoticeLinkStart)
		writeNoticeText(&out, mask, true)
		out.WriteString(replyNoticeLinkEnd)
	}
	return out.String()
}

// Entities keep arbitrary labels and masks within one link. Line breaks
// and tabs are shown explicitly so they do not end the notice or hide text.
func writeNoticeText(out *strings.Builder, text string, title bool) {
	for _, c := range text {
		switch c {
		case '\n':
			out.WriteRune('⏎')
		case '\r':
			out.WriteRune('␍')
		case '\t':
			out.WriteRune('⇥')
		default:
			if unicode.IsControl(c) {
				out.WriteRune('�')
			} else if strings.ContainsRune("&\\<>\"", c) || !title && strings.ContainsRune("[]`*_~", c) {
				out.WriteString("&#" + strconv.Itoa(int(c)) + ";")
			} else {
				out.WriteRune(c)
			}
		}
	}
}

// StripReplyNotices keeps reply presentation out of assistant history
// before routing, even when this request uses no masker. Older preview
// notices with the same link target can have a different heading.
func StripReplyNotices(body []byte) []byte {
	jsonBody := bytes.TrimLeft(body, " \t\r\n")
	if len(jsonBody) == 0 || jsonBody[0] != '{' {
		return body
	}
	if !bytes.Contains(body, []byte(replyNoticeTarget)) && !bytes.Contains(body, []byte(`\u`)) {
		return body
	}
	out, _ := walk(body, func(path, _, text string) string {
		plain := stripReplyNotice(text)
		if len(plain) == len(text) {
			return text
		}
		parts := strings.Split(path, ".")
		if (len(parts) != 3 && len(parts) != 5) ||
			(parts[0] != "messages" && parts[0] != "input") || parts[2] != "content" {
			return text
		}
		item := parts[0] + "." + parts[1]
		if gjson.GetBytes(body, item+".role").String() != "assistant" {
			return text
		}
		if len(parts) == 3 {
			return plain
		}
		kind := gjson.GetBytes(body, item+".content."+parts[3]+".type").String()
		if parts[4] == "text" && (kind == "text" || kind == "output_text") {
			return plain
		}
		return text
	})
	return out
}

func stripReplyNotice(text string) string {
	const paragraph = "\n\n"
	if !strings.Contains(text, replyNoticeLinkStart) {
		return text
	}
	trimmed := strings.TrimRight(text, "\r\n")
	listAt := strings.LastIndex(trimmed, paragraph)
	if listAt < 0 {
		return text
	}
	headingAt := strings.LastIndex(trimmed[:listAt], paragraph)
	if headingAt < 0 {
		return text
	}
	heading := trimmed[headingAt+len(paragraph) : listAt]
	if heading == "" || strings.ContainsRune(heading, '\n') {
		return text
	}
	list := trimmed[listAt+len(paragraph):]
	for line := range strings.SplitSeq(list, "\n") {
		if !strings.HasPrefix(line, replyNoticeListStart) || !strings.Contains(line, replyNoticeLinkStart) || !strings.HasSuffix(line, replyNoticeLinkEnd) {
			return text
		}
	}
	return text[:headingAt]
}
