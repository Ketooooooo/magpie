package privacyengine

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/yetone/magpie/internal/privacyengine/internal/pii"
	"github.com/yetone/magpie/internal/settings"
)

type BuiltinModelStatus struct {
	On bool `json:"on"`
	// Chosen says the user turned it on, not the default: only then is
	// a request held back for it (masking.ModelOn)
	Chosen bool `json:"chosen,omitempty"`
	pii.Status
	MinScore     float64      `json:"minScore"`
	DefaultScore float64      `json:"defaultScore"`
	Models       []pii.Status `json:"models"`
}

// modelOf and models are pii's; vars for tests.
var modelOf, models = pii.Of, pii.Models

func BuiltinModelState() BuiltinModelStatus {
	st := settings.Load()
	on := BuiltinModelWanted(st)
	m := modelOf(pii.Choose(st.RedactModelName, on))
	out := BuiltinModelStatus{On: on, Chosen: st.RedactModel, Status: m.Now(), MinScore: pii.Threshold(st.RedactModelScore, m), DefaultScore: m.MinScore()}
	for _, m := range models() {
		out.Models = append(out.Models, m.Now())
	}
	return out
}

// BuiltinModelCommand: GET /api/privacy-model is its state; POST with
// {"do": "on" | "off" | "cancel" | "remove" | "pick" | "score", "model": id,
// "score": s} turns
// it on (as model, or the one it would use: downloading it first, and
// saving it on once that is done), off (a download is stopped, the model
// let go and kept), stops a download, turns it off and deletes every
// model downloaded, or picks model: while it is on, that is turning it on
// as model (the one before masks until model is downloaded); while off,
// the pick is kept for turning it on; score keeps s as the threshold of
// model (the one masking uses, with none), 0 for its default.
type BuiltinModelCommand struct {
	Do    string  `json:"do"`
	Model string  `json:"model"`
	Score float64 `json:"score"`
}

func ApplyBuiltinModel(in BuiltinModelCommand) error {
	if in.Model != "" && in.Model != pii.PrivacyFilter && in.Model != pii.AstrLinkGuard {
		return fmt.Errorf("model is %s or %s, not %q", pii.PrivacyFilter, pii.AstrLinkGuard, in.Model)
	}
	st, err := settings.LoadChecked()
	if err != nil {
		return err
	}
	if ID(st) != Builtin {
		return ErrBuiltinSettings
	}
	on := BuiltinModelWanted(st)
	was := pii.Choose(st.RedactModelName, on)
	switch in.Do {
	case "pick":
		switch {
		case in.Model == "":
			err = fmt.Errorf("pick needs a model")
		case on:
			err = turnOn(in.Model, was)
		default:
			err = settings.SetRedactModelName(in.Model)
		}
	case "score":
		id := in.Model
		if id == "" {
			id = was
		}
		if in.Score != 0 && !(in.Score >= pii.Floor && in.Score < 1) {
			err = fmt.Errorf("score is 0 (the model's own) or from %g to under 1, not %g", pii.Floor, in.Score)
		} else {
			err = settings.SetRedactModelScore(id, in.Score)
		}
	case "on":
		id := in.Model
		if id == "" {
			id = was
		}
		err = turnOn(id, was)
	case "off":
		for _, m := range models() {
			m.Cancel()
		}
		err = settings.SetRedactModel(false)
		for _, m := range models() {
			m.Stop()
		}
	case "cancel":
		for _, m := range models() {
			m.Cancel()
		}
		// the download on by default, cancelled, is the model
		// turned off: it would start again on the next request
		if on && !st.RedactModel && !modelOf(was).Installed() {
			err = settings.SetRedactModel(false)
		}
	case "remove":
		if err = settings.SetRedactModel(false); err == nil {
			for _, m := range models() {
				if e := m.Remove(); e != nil && err == nil {
					err = e
				}
			}
		}
	default:
		err = fmt.Errorf("do is on, off, cancel, remove, pick or score, not %q", in.Do)
	}
	return err
}

// turnOn turns the local model on as id, once it is on disk: a request
// in between is masked as before (by the rules, or by was, the model on
// till then), and not held back. A download of another model under way
// is stopped; was is let go once id masks.
func turnOn(id, was string) error {
	m := modelOf(id)
	if !m.Supported() {
		return fmt.Errorf("the local masking model doesn't run on this system yet")
	}
	for _, o := range models() {
		if o.ID() != id {
			o.Cancel()
		}
	}
	on := func() {
		if settings.UseRedactModel(id) == nil {
			if was != id {
				modelOf(was).Stop()
			}
			m.Warm()
		}
	}
	if m.Installed() {
		on()
		return nil
	}
	return m.Download(on)
}

// RemoveBuiltinModels removes local model assets during uninstall.
func RemoveBuiltinModels() error { return pii.Remove() }

// FetchModelAsset downloads a checksum-verified model asset.
func FetchModelAsset(ctx context.Context, url, path string, size int64, digest string, progress *atomic.Int64) error {
	return pii.Fetch(ctx, url, path, size, digest, progress)
}

func GuardForTest() pii.Model {
	if !testing.Testing() {
		panic("test-only privacy model")
	}
	return pii.Of(pii.AstrLinkGuard)
}
