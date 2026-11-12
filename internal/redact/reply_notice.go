package redact

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	replyNoticeMarker = "#magpie-privacy-notice"
	replyNoticeStart  = "\n\n[magpie-privacy-notice-start]: " + replyNoticeMarker + "\n\n"
	replyNoticeEnd    = "\n\n[magpie-privacy-notice-end]: " + replyNoticeMarker
)

func wrapReplyNotice(notice string) string {
	return replyNoticeStart + strings.TrimLeft(notice, "\n") + replyNoticeEnd
}

// StripReplyNotices keeps reply presentation out of assistant history
// before routing, even when this request uses no masker.
func StripReplyNotices(body []byte) []byte {
	jsonBody := bytes.TrimLeft(body, " \t\r\n")
	if len(jsonBody) == 0 || jsonBody[0] != '{' {
		return body
	}
	if !bytes.Contains(body, []byte(replyNoticeMarker)) &&
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
	tailTrimmed := strings.TrimRight(text, "\r\n")
	if beforeEnd, ok := strings.CutSuffix(tailTrimmed, replyNoticeEnd); ok {
		if start := strings.LastIndex(beforeEnd, replyNoticeStart); start >= 0 {
			return beforeEnd[:start]
		}
	}
	// Gray previews created before Magpie wrapped notices used this footer.
	const grayHeading = "\n\n🔒 Gray masked the following values before sending them to the model.\n\n"
	start := strings.LastIndex(tailTrimmed, grayHeading)
	if start >= 0 {
		tail := tailTrimmed[start+len(grayHeading):]
		if tail != "" {
			for line := range strings.SplitSeq(tail, "\n") {
				if !strings.HasPrefix(line, "- [") || !strings.Contains(line, `](#gray-mask "`) || !strings.HasSuffix(line, `")`) {
					return text
				}
			}
			return text[:start]
		}
	}
	return text
}
