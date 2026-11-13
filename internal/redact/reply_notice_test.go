package redact

import (
	"html"
	"strings"
	"testing"
)

func TestReplyNoticeEscapesArbitraryValues(t *testing.T) {
	const original = "[secret](https://example.org) *with* `Markdown` & literal &#34;\nnext"
	const mask = "mask \\ \" ](https://example.org) <b> & literal &#34;\r\nnext"
	notice := FormatReplyNotice(map[string]string{mask: original, "other mask": "other value"})
	lines := strings.Split(notice, "\n")
	if len(lines) != 6 || lines[2] != replyNoticeHeading {
		t.Fatalf("unexpected notice layout: %q", notice)
	}
	label, title, ok := strings.Cut(strings.TrimPrefix(lines[4], "- ["), replyNoticeLinkStart)
	title, closed := strings.CutSuffix(title, replyNoticeLinkEnd)
	if !ok || !closed || strings.ContainsAny(label, "[]`*") || strings.ContainsAny(title, "\\\"<>") {
		t.Fatalf("unescaped Markdown in link: %q", lines[4])
	}
	if got := html.UnescapeString(label); got != strings.ReplaceAll(original, "\n", "⏎") {
		t.Fatalf("unexpected displayed value: %q", got)
	}
	if got := html.UnescapeString(title); got != strings.ReplaceAll(mask, "\r\n", "␍⏎") {
		t.Fatalf("unexpected hover mask: %q", got)
	}
	if got := stripReplyNotice("An answer." + notice); got != "An answer." {
		t.Fatalf("could not strip the full notice: %q", got)
	}
}
