package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yetone/magpie/internal/filememo"
	"github.com/yetone/magpie/internal/lazyre"
)

// PrivacyLauncher is the command a plugin declares in magpie.privacyModels.
// Its model's local path is appended to Args. Only a plugin's package may
// declare the launcher; saved Options supply model versions and paths.
type PrivacyLauncher struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Version string   `json:"-"`
}

// PrivacyModels reads a plugin's launcher and whether it has no host entry.
func PrivacyModels(target string) (*PrivacyLauncher, bool) {
	type manifest struct {
		Main    string          `json:"main"`
		Exports json.RawMessage `json:"exports"`
		Version string          `json:"version"`
		Magpie  struct {
			Privacy *PrivacyLauncher `json:"privacyModels"`
		} `json:"magpie"`
	}
	pkg, err := filememo.Read("privacy-models", filepath.Join(target, "package.json"), func(data []byte) (manifest, error) {
		var m manifest
		err := json.Unmarshal(data, &m)
		return m, err
	})
	if err != nil || pkg.Magpie.Privacy == nil || strings.TrimSpace(pkg.Magpie.Privacy.Command) == "" {
		return nil, false
	}
	launcher := *pkg.Magpie.Privacy
	launcher.Command = strings.TrimSpace(launcher.Command)
	launcher.Version = pkg.Version
	return &launcher, pkg.Main == "" && (len(pkg.Exports) == 0 || string(pkg.Exports) == "null")
}

// PrivacyVersion is one selectable model from a plugin's Options.models.
type PrivacyVersion struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Path     string  `json:"path"`
	Revision string  `json:"revision,omitempty"`
	MinScore float64 `json:"minScore,omitempty"`
}

var privacyID = lazyre.New(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// PrivacyVersions checks a plugin's saved model configurations.
func PrivacyVersions(options map[string]any) ([]PrivacyVersion, error) {
	models, ok := options["models"]
	if !ok {
		return nil, nil
	}
	data, err := json.Marshal(models)
	if err != nil {
		return nil, err
	}
	var versions []PrivacyVersion
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&versions); err != nil {
		return nil, fmt.Errorf("invalid privacy model options: %w", err)
	}
	seen := make(map[string]bool, len(versions))
	for i, v := range versions {
		if !privacyID.MatchString(v.ID) || seen[v.ID] {
			return nil, fmt.Errorf("privacy models[%d]: invalid or duplicate id %q", i, v.ID)
		}
		if strings.TrimSpace(v.Name) == "" || !filepath.IsAbs(v.Path) || !(v.MinScore >= 0 && v.MinScore < 1) {
			return nil, fmt.Errorf("privacy models[%d]: give a name, an absolute path and a minScore from 0 to under 1", i)
		}
		seen[v.ID] = true
	}
	return versions, nil
}
