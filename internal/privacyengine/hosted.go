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
	"github.com/yetone/magpie/internal/settings"
)

var pluginUnavailable = errors.New("The privacy plugin could not protect this request; nothing was sent")

func pluginDataPath(identity, id string) string {
	hash := sha256.Sum256([]byte(identity + "\x00" + id))
	return filepath.Join(settings.Dir(), "privacy-engines", hex.EncodeToString(hash[:]))
}

func hostedEngine(entry plugin.Entry, spec plugin.PrivacySpec) engine {
	target, directory := plugin.Target(entry.Spec), pluginDataPath(plugin.Name(entry.Spec), spec.ID)
	begin := func(ctx context.Context, in engineInput, out *protectedInput) (*plugin.PrivacyStream, error) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
		return plugin.BeginPrivacyStream(ctx, target, spec, directory, in, out)
	}
	preview := func(ctx context.Context, text string) (string, []gwmw.Hit, bool, error) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return "", nil, false, pluginUnavailable
		}
		var out protectedInput
		if err := plugin.PreviewPrivacy(ctx, target, spec, directory, engineInput{Texts: []string{text}}, &out); err != nil || len(out.Texts) != 1 {
			return "", nil, false, pluginUnavailable
		}
		return out.Texts[0], out.Hits, false, nil
	}
	return engine{
		info: Info{ID: spec.ID, Name: spec.Name, Off: entry.Off},
		check: func(ctx context.Context) error {
			_, _, _, err := preview(ctx, "Magpie privacy readiness check.")
			return err
		},
		begin: func(ctx context.Context, _ settings.Settings, _ bool) (context.Context, gwmw.Masker, error) {
			return ctx, &pluginMasker{ctx: ctx, name: spec.Name, begin: begin}, nil
		},
		preview: preview,
	}
}
