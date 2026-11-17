package privacyengine

import (
	"context"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/masking"
	"github.com/yetone/magpie/internal/settings"
)

func nativeEngine() engine {
	return engine{
		info:   Info{ID: Builtin, Name: "Magpie", Builtin: true},
		wanted: masking.Wanted,
		begin: func(ctx context.Context, st settings.Settings, forced bool) (context.Context, gwmw.Masker, error) {
			wanted := masking.Wanted(st)
			m, err := gwmw.Masking(forced || wanted)
			if forced && !wanted && err == nil {
				if _, ok := m.(gwmw.ContextTeller); !ok {
					return ctx, nil, gwmw.ErrUnmasked
				}
				ctx = masking.WithForced(ctx)
			}
			return ctx, m, err
		},
		preview: func(_ context.Context, input string) (string, []gwmw.Hit, bool, error) {
			text, hits, off := masking.Preview(input)
			return text, hits, off, nil
		},
	}
}
