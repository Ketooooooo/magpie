package privacyengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/redact"
	"github.com/yetone/magpie/internal/settings"
)

var pluginUnavailable = errors.New("The privacy plugin could not protect this request; nothing was sent")

func pluginDataPath(identity, id string) string {
	hash := sha256.Sum256([]byte(identity + "\x00" + id))
	return filepath.Join(settings.Dir(), "privacy-engines", hex.EncodeToString(hash[:]))
}

func hostedEngine(entry plugin.Entry, spec plugin.PrivacySpec) engine {
	target, directory := plugin.Target(entry.Spec), pluginDataPath(plugin.Name(entry.Spec), spec.ID)
	scan := func(ctx context.Context, fragments []redact.Fragment, version *uint64, preview bool) ([]scanReport, uint64, error) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, 0, pluginUnavailable
		}
		var reply struct {
			Version *uint64      `json:"version"`
			Reports []scanReport `json:"reports"`
		}
		if err := plugin.ProtectWithPlugin(ctx, target, spec, directory, fragments, version, preview, &reply); err != nil {
			return nil, 0, pluginUnavailable
		}
		if reply.Version == nil {
			return nil, 0, pluginUnavailable
		}
		return reply.Reports, *reply.Version, nil
	}
	run := func(ctx context.Context, fragments []redact.Fragment, version *uint64) ([]scanReport, uint64, error) {
		return scan(ctx, fragments, version, false)
	}
	preview := func(ctx context.Context, text string) (string, []gwmw.Hit, bool, error) {
		return pluginPreview(ctx, text, spec.Name, func(ctx context.Context, fragments []redact.Fragment, version *uint64) ([]scanReport, uint64, error) {
			return scan(ctx, fragments, version, true)
		})
	}
	return engine{
		info: Info{ID: spec.ID, Name: spec.Name, Off: entry.Off},
		check: func(ctx context.Context) error {
			_, _, _, err := preview(ctx, "Magpie privacy readiness check.")
			return err
		},
		validate: compatible,
		begin: func(ctx context.Context, _ settings.Settings, _ bool) (context.Context, gwmw.Masker, error) {
			masker := newPluginMasker(ctx, spec.Name, run)
			if spec.ReplyNotice {
				masker.notice = func(ctx context.Context, values map[string]string) string {
					notice, err := plugin.PrivacyNotice(ctx, target, spec, values)
					if err != nil {
						return ""
					}
					return notice
				}
			}
			return ctx, masker, nil
		},
		preview: preview,
	}
}

func compatible(st settings.Settings) error {
	if st.RedactRouteTo != "" || len(st.RedactActions) != 0 || len(st.RedactAllow) != 0 ||
		len(st.RedactWords) != 0 || len(st.RedactRules) != 0 {
		return errors.New("This privacy plugin cannot use the current Magpie custom masking rules, exceptions, actions or alternate route")
	}
	return nil
}
