package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/privacyengine"
	"github.com/yetone/magpie/internal/settings"
)

var pluginUnavailable = errors.New("The privacy plugin could not protect this request; nothing was sent")

func init() { privacyengine.RegisterHostedEngines(hostedPrivacyEngines) }

func hostedPrivacyEngines() []privacyengine.HostedEngine {
	var engines []privacyengine.HostedEngine
	for _, entry := range Load().Plugins {
		target := Target(entry.Spec)
		if spec, _ := Privacy(target); spec != nil {
			hash := sha256.Sum256([]byte(Name(entry.Spec) + "\x00" + spec.ID))
			directory := filepath.Join(settings.Dir(), "privacy-engines", hex.EncodeToString(hash[:]))
			engines = append(engines, hostedPrivacyEngine{
				spec: *spec, target: target, directory: directory, off: entry.Off,
			})
		}
	}
	return engines
}

type hostedPrivacyEngine struct {
	spec              PrivacySpec
	target, directory string
	off               bool
}

func (e hostedPrivacyEngine) Info() privacyengine.Info {
	return privacyengine.Info{ID: e.spec.ID, Name: e.spec.Name, Off: e.off}
}

func (e hostedPrivacyEngine) Begin(ctx context.Context) gwmw.Masker {
	return &pluginMasker{ctx: ctx, begin: e.begin}
}

func (e hostedPrivacyEngine) begin(ctx context.Context, input engineInput, out *protectedInput) (*privacyStream, error) {
	if err := os.MkdirAll(e.directory, 0o700); err != nil {
		return nil, err
	}
	return beginPrivacyStream(ctx, e.target, e.spec, e.directory, input, out)
}

func (e hostedPrivacyEngine) Preview(ctx context.Context, text string) (string, []gwmw.Hit, error) {
	if err := os.MkdirAll(e.directory, 0o700); err != nil {
		return "", nil, pluginUnavailable
	}
	var out protectedInput
	if err := previewPrivacy(ctx, e.target, e.spec, e.directory, engineInput{Texts: []string{text}}, &out); err != nil || len(out.Texts) != 1 {
		return "", nil, pluginUnavailable
	}
	return out.Texts[0], out.Hits, nil
}

func (e hostedPrivacyEngine) ApplyRecordAction(ctx context.Context, action gwmw.RecordAction) error {
	return applyPrivacyRecordAction(ctx, e.target, e.spec, e.directory, action)
}
