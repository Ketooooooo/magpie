package gateway

import (
	"net/http"

	"github.com/yetone/magpie/internal/access"
)

func privacyTaskKey(r *http.Request, kind, id string) string {
	if id == "" {
		return ""
	}
	return access.Caller(r.Context()).KeyID + "\x00" + kind + "\x00" + id
}
