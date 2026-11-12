// Package privacyengine selects a registered privacy engine for a gateway request.
package privacyengine

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/settings"
)

const Builtin = "magpie"

// Info is safe to return to the settings page. Connection credentials stay local.
type Info struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Builtin    bool   `json:"builtin,omitempty"`
	Configured bool   `json:"configured"`
	Endpoint   string `json:"endpoint,omitempty"`
	Off        bool   `json:"off,omitempty"`
	Conflict   bool   `json:"conflict,omitempty"`
}

type engine struct {
	info     Info
	wanted   func(settings.Settings) bool
	check    func(context.Context) error
	validate func(settings.Settings) error
	begin    func(context.Context, settings.Settings, bool) (context.Context, gwmw.Masker, error)
	preview  func(context.Context, string) (string, []gwmw.Hit, bool, error)
	remote   *companion
}

type registry map[string]engine

func (r registry) register(e engine) {
	if old, exists := r[e.info.ID]; exists {
		old.info.Conflict = true
		r[e.info.ID] = old
		return
	}
	r[e.info.ID] = e
}

func registered() registry {
	r := registry{}
	r.register(nativeEngine())
	for _, entry := range plugin.Load().Plugins {
		if spec, _ := plugin.Privacy(plugin.Target(entry.Spec)); spec != nil {
			r.register(companionEngine(entry, *spec))
		}
	}
	return r
}

func Catalog() []Info {
	var out []Info
	for _, engine := range registered() {
		out = append(out, engine.info)
	}
	slices.SortFunc(out, func(a, b Info) int {
		if a.Builtin != b.Builtin {
			if a.Builtin {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

func ID(st settings.Settings) string {
	if st.PrivacyEngine == "" {
		return Builtin
	}
	return st.PrivacyEngine
}

// The default engine is registered through the same registry. It can be
// resolved without reading installed packages on Magpie's normal hot path.
func lookup(id string) (engine, error) {
	r := registry{}
	if id == Builtin {
		r.register(nativeEngine())
	} else {
		r = registered()
	}
	e, ok := r[id]
	if !ok || e.info.Off {
		return engine{}, errors.New("The selected privacy plugin is unavailable. Install or enable it in Plugins, or select another engine")
	}
	if e.info.Conflict {
		return engine{}, errors.New("More than one installed privacy plugin uses this engine ID")
	}
	return e, nil
}

func Select(ctx context.Context, id string) error {
	e, err := lookup(id)
	if err != nil {
		return err
	}
	if e.check != nil {
		if err := e.check(ctx); err != nil {
			return err
		}
	}
	return settings.SetPrivacyEngine(id, e.validate)
}

func Wanted(st settings.Settings) bool {
	// A selected external engine remains required if its plugin is removed.
	return ID(st) != Builtin || nativeEngine().wanted(st)
}

func Begin(ctx context.Context, st settings.Settings, forced bool) (context.Context, gwmw.Masker, error) {
	e, err := lookup(ID(st))
	if err != nil {
		return ctx, nil, err
	}
	if e.validate != nil {
		if err := e.validate(st); err != nil {
			return ctx, nil, err
		}
	}
	return e.begin(ctx, st, forced)
}

func Preview(ctx context.Context, st settings.Settings, input string) (string, []gwmw.Hit, bool, error) {
	e, err := lookup(ID(st))
	if err != nil {
		return "", nil, false, err
	}
	if e.validate != nil {
		if err := e.validate(st); err != nil {
			return "", nil, false, err
		}
	}
	return e.preview(ctx, input)
}

func Configure(ctx context.Context, id, endpoint, token string) error {
	e, err := lookup(id)
	if err != nil {
		return err
	}
	if e.remote == nil {
		return errors.New("This engine does not use a companion service")
	}
	return e.remote.configure(ctx, endpoint, token)
}
