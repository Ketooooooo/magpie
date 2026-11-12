// Package privacyengine selects a privacy engine and binds it to a gateway request.
package privacyengine

import (
	"context"
	"errors"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/masking"
	"github.com/yetone/magpie/internal/settings"
)

const Builtin = "magpie"

type adapter struct {
	check    func(context.Context) error
	validate func(settings.Settings) error
	begin    func(context.Context) gwmw.Masker
}

var engines = map[string]adapter{
	Builtin: {},
	"gray":  {check: checkGray, validate: compatible, begin: newGray},
}

func ID(st settings.Settings) string {
	if st.PrivacyEngine == "" {
		return Builtin
	}
	return st.PrivacyEngine
}

func Select(ctx context.Context, id string) error {
	engine, ok := engines[id]
	if !ok {
		return errors.New("Unknown privacy engine")
	}
	if engine.check != nil {
		if err := engine.check(ctx); err != nil {
			return err
		}
	}
	return settings.SetPrivacyEngine(id, func(st settings.Settings) error {
		if engine.validate != nil {
			return engine.validate(st)
		}
		return nil
	})
}

func Wanted(st settings.Settings) bool {
	return ID(st) != Builtin || masking.Wanted(st)
}

func Begin(ctx context.Context, st settings.Settings, forced bool) (context.Context, gwmw.Masker, error) {
	if ID(st) == Builtin {
		m, err := gwmw.Masking(forced || masking.Wanted(st))
		if forced && !masking.Wanted(st) && err == nil {
			if _, ok := m.(gwmw.ContextTeller); !ok {
				return ctx, nil, gwmw.ErrUnmasked
			}
			ctx = masking.WithForced(ctx)
		}
		return ctx, m, err
	}
	engine, ok := engines[ID(st)]
	if !ok || engine.begin == nil {
		return ctx, nil, gwmw.ErrUnmasked
	}
	if engine.validate != nil {
		if err := engine.validate(st); err != nil {
			return ctx, nil, err
		}
	}
	return ctx, engine.begin(ctx), nil
}

func Preview(ctx context.Context, st settings.Settings, input string) (string, []gwmw.Hit, bool, error) {
	if ID(st) == Builtin {
		text, hits, off := masking.Preview(input)
		return text, hits, off, nil
	}
	ctx, m, err := Begin(ctx, st, false)
	if err != nil {
		return "", nil, false, err
	}
	type result struct {
		text string
		hits []gwmw.Hit
	}
	out, err := gwmw.Safely(func() result {
		text, hits := m.(gwmw.ContextTeller).TextHitsContext(ctx, input)
		return result{text, hits}
	})
	return out.text, out.hits, false, err
}
