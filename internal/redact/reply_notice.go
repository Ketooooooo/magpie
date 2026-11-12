package redact

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
)

const ReplyNoticeTarget = "#magpie-privacy-notice"

// StripReplyNotices keeps reply presentation out of assistant history
// before routing, even when this request uses no masker.
func StripReplyNotices(body []byte) []byte {
	jsonBody := bytes.TrimLeft(body, " \t\r\n")
	if len(jsonBody) == 0 || jsonBody[0] != '{' {
		return body
	}
	if !bytes.Contains(body, []byte(ReplyNoticeTarget)) &&
		!bytes.Contains(body, []byte("#gray-mask")) &&
		!bytes.Contains(body, []byte(`\u`)) {
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
	trimmed := strings.TrimRight(text, "\r\n")
	// Notices from the reference-definition preview already in history.
	if beforeEnd, ok := strings.CutSuffix(trimmed, paragraph+"[magpie-privacy-notice-end]: "+ReplyNoticeTarget); ok {
		if start := strings.LastIndex(beforeEnd, paragraph+"[magpie-privacy-notice-start]: "+ReplyNoticeTarget+paragraph); start >= 0 {
			return beforeEnd[:start]
		}
	}
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
	target := ReplyNoticeTarget
	// Existing Gray conversations use the older link target.
	if heading == "🔒 Gray masked the following values before sending them to the model." && !strings.Contains(list, ReplyNoticeTarget) {
		target = "#gray-mask"
	}
	for line := range strings.SplitSeq(list, "\n") {
		if !strings.HasPrefix(line, "- [") || !strings.Contains(line, "]("+target+` "`) || !strings.HasSuffix(line, `")`) {
			return text
		}
	}
	return text[:headingAt]
}
