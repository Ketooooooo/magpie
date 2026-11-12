package plugin

import (
	"encoding/json"
	"io"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/yetone/magpie/internal/lazyre"
)

// PrivacySpec declares a companion engine that implements the local scan protocol.
type PrivacySpec struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	StatePath   string `json:"statePath"`
	ScanPath    string `json:"scanPath"`
	TokenHeader string `json:"tokenHeader"`
}

var privacyPath = lazyre.New(`^/[a-zA-Z0-9_/-]+$`)
var privacyHeader = lazyre.New(`^X-[A-Za-z0-9-]{1,60}$`)

// Privacy reads a plugin's declaration without loading any of its code.
func Privacy(target string) (spec *PrivacySpec, only bool) {
	f, err := os.Open(filepath.Join(target, "package.json"))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var pkg struct {
		Main    string          `json:"main"`
		Exports json.RawMessage `json:"exports"`
		Magpie  struct {
			Privacy *PrivacySpec `json:"privacy"`
		} `json:"magpie"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 256<<10))
	if decoder.Decode(&pkg) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, false
	}
	s := pkg.Magpie.Privacy
	if s == nil || !actionID.MatchString(s.ID) || s.ID == "magpie" || s.Protocol != "http-scan-v1" {
		return nil, false
	}
	s.Name = strings.TrimSpace(s.Name)
	s.TokenHeader = textproto.CanonicalMIMEHeaderKey(s.TokenHeader)
	if s.Name == "" || len(s.Name) > 100 || strings.ContainsFunc(s.Name, unicode.IsControl) ||
		!privacyHeader.MatchString(s.TokenHeader) || !validPrivacyPath(s.StatePath) || !validPrivacyPath(s.ScanPath) ||
		s.StatePath == s.ScanPath {
		return nil, false
	}
	return s, pkg.Main == "" && len(pkg.Exports) == 0
}

func validPrivacyPath(p string) bool {
	return len(p) <= 180 && privacyPath.MatchString(p) && path.Clean(p) == p
}
