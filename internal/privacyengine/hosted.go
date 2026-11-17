package privacyengine

import (
	"context"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/settings"
)

// HostedEngine is the contract the plugin host implements for the engine
// registry. Callers use Begin, Preview and ApplyRecordAction on this package.
type HostedEngine interface {
	Info() Info
	Begin(context.Context) gwmw.Masker
	Preview(context.Context, string) (string, []gwmw.Hit, error)
	ApplyRecordAction(context.Context, gwmw.RecordAction) error
}

var loadHostedEngines func() []HostedEngine

// RegisterHostedEngines installs the plugin host's engine discovery during init.
func RegisterHostedEngines(load func() []HostedEngine) {
	if loadHostedEngines != nil {
		panic("hosted privacy engines already registered")
	}
	loadHostedEngines = load
}

func hostedEngine(hosted HostedEngine) engine {
	return engine{
		info: hosted.Info(),
		check: func(ctx context.Context) error {
			_, _, err := hosted.Preview(ctx, "Magpie privacy readiness check.")
			return err
		},
		begin: func(ctx context.Context, _ settings.Settings, _ bool) (context.Context, gwmw.Masker, error) {
			return ctx, hosted.Begin(ctx), nil
		},
		preview: func(ctx context.Context, text string) (string, []gwmw.Hit, bool, error) {
			out, hits, err := hosted.Preview(ctx, text)
			return out, hits, false, err
		},
		actions: hostedActions{applyAction: hosted.ApplyRecordAction},
	}
}
