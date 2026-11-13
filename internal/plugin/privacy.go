package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// PrivacySpec declares an engine loaded by the existing Bun plugin host.
type PrivacySpec struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Entry       string `json:"entry"`
	ReplyNotice bool   `json:"replyNotice"`
}

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
	if s == nil || !actionID.MatchString(s.ID) || (s.ID == "magpie" || s.ID == "none") {
		return nil, false
	}
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" || len(s.Name) > 100 || strings.ContainsFunc(s.Name, unicode.IsControl) {
		return nil, false
	}
	if s.Protocol != "plugin-scan-v1" || !fs.ValidPath(s.Entry) || !filepath.IsLocal(filepath.FromSlash(s.Entry)) ||
		!strings.HasSuffix(s.Entry, ".mjs") {
		return nil, false
	}
	return s, pkg.Main == "" && len(pkg.Exports) == 0
}

// ProtectWithPlugin calls the package in the existing Bun host. The entry is
// resolved inside the installed package before any unmasked text is passed.
func ProtectWithPlugin(ctx context.Context, target string, spec PrivacySpec, directory string, fragments any, preview bool, output any) error {
	root, err := os.OpenRoot(target)
	if err != nil {
		return errors.New("The privacy plugin package is unavailable")
	}
	defer root.Close()
	file, err := root.Stat(filepath.FromSlash(spec.Entry))
	if err != nil || !file.Mode().IsRegular() {
		return errors.New("The privacy plugin entry is unavailable")
	}
	return Call(ctx, "privacyProtect", map[string]any{
		"entry":     filepath.Join(target, filepath.FromSlash(spec.Entry)),
		"directory": directory, "fragments": fragments,
		"preview": preview,
	}, output)
}
