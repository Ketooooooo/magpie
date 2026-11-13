package redact

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	replyNoticeTarget    = "#magpie-privacy-notice"
	replyNoticeListStart = "- ["
	replyNoticeLinkStart = "](" + replyNoticeTarget + ` "`
	replyNoticeLinkEnd   = `")`
)

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
