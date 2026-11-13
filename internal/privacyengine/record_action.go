package privacyengine

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/maskrec"
	"github.com/yetone/magpie/internal/settings"
)

const maskBlockedKinds = "mask-blocked-kinds"
const allowValuePrefix = "never-mask:"

// Engines that offer record actions implement both halves of the contract.
type recordActionHandler interface {
	offers(maskrec.Record, []gwmw.Hit) []gwmw.RecordAction
	apply(context.Context, gwmw.RecordAction) error
}

// BlockedRecordActions collects the originating engine's offers before
// hits are merged for display. An ID must name exactly one action.
func BlockedRecordActions(record maskrec.Record, hits []gwmw.Hit) []gwmw.RecordAction {
	engine, err := lookup(cmp.Or(record.Engine, Builtin))
	if err != nil || engine.actions == nil {
		return nil
	}
	return engine.actions.offers(record, hits)
}

type hostedActions struct {
	applyAction func(context.Context, gwmw.RecordAction) error
}

func (h hostedActions) apply(ctx context.Context, action gwmw.RecordAction) error {
	return h.applyAction(ctx, action)
}

func (hostedActions) offers(_ maskrec.Record, hits []gwmw.Hit) []gwmw.RecordAction {
	var actions []gwmw.RecordAction
	seen := map[string]gwmw.RecordAction{}
	for _, hit := range hits {
		action := hit.RecordAction
		if hit.Action != "block" || action == nil || action.ID == "" || action.Label == "" || action.TargetRef == "" {
			continue
		}
		if previous, ok := seen[action.ID]; ok {
			if previous != *action {
				seen[action.ID] = gwmw.RecordAction{}
				actions = slices.DeleteFunc(actions, func(a gwmw.RecordAction) bool { return a.ID == action.ID })
			}
			continue
		}
		seen[action.ID] = *action
		actions = append(actions, *action)
	}
	return actions
}

func RecordActions(record maskrec.Record) []gwmw.RecordAction {
	if len(record.Actions) == 0 && cmp.Or(record.Engine, Builtin) == Builtin {
		return BlockedRecordActions(record, nil)
	}
	return record.Actions
}

// ApplyRecordAction accepts only an action offered on the stored record.
// The active engine may have changed since that request.
func ApplyRecordAction(ctx context.Context, key int64, id string) error {
	record, ok := maskrec.Get(key)
	if !ok {
		return errors.New("This masking record is no longer available")
	}
	for _, action := range RecordActions(record) {
		if action.ID != id {
			continue
		}
		if action.DisabledReason != "" {
			return errors.New(action.DisabledReason)
		}
		engine, err := lookup(cmp.Or(record.Engine, Builtin))
		if err != nil {
			return err
		}
		if engine.actions == nil {
			break
		}
		return engine.actions.apply(ctx, action)
	}
	return errors.New("This action is unavailable for this masking record")
}

type builtinActions struct{}

func (builtinActions) offers(record maskrec.Record, _ []gwmw.Hit) []gwmw.RecordAction {
	if !record.Blocked {
		var actions []gwmw.RecordAction
		for _, value := range record.Values {
			if value.Action != "warn" && value.Placeholder != "" {
				actions = append(actions, gwmw.RecordAction{
					ID: allowValuePrefix + value.Placeholder, Label: "Never mask", Placeholder: value.Placeholder, TargetRef: value.Placeholder,
					DisabledReason: builtinAllowDisabled(value.By),
				})
			}
		}
		return actions
	}
	var kinds []string
	for _, value := range record.Values {
		if value.Action == "block" && !slices.Contains(kinds, value.Kind) {
			kinds = append(kinds, value.Kind)
		}
	}
	if len(kinds) == 0 {
		return nil
	}
	label := "Mask this category instead"
	if len(kinds) > 1 {
		label = "Mask these categories instead"
	}
	return []gwmw.RecordAction{{
		ID:        maskBlockedKinds,
		Label:     label,
		Scope:     strings.Join(kinds, ", "),
		TargetRef: strings.Join(kinds, ","),
	}}
}

func builtinAllowDisabled(by string) string {
	if by == "word" {
		return "One of your Masked words"
	}
	return ""
}

func (builtinActions) apply(_ context.Context, action gwmw.RecordAction) error {
	if action.ID == allowValuePrefix+action.TargetRef {
		value, ok := builtinRecordValue(action.TargetRef)
		if !ok {
			return errors.New("The engine no longer remembers this value")
		}
		return settings.EditBuiltinPrivacy(func(s *settings.Settings) error {
			s.RedactAllow = append(s.RedactAllow, value)
			return nil
		})
	}
	if action.ID != maskBlockedKinds {
		return errors.New("This action is unavailable for the built-in privacy engine")
	}
	return settings.EditBuiltinPrivacy(func(s *settings.Settings) error {
		kinds := strings.Split(action.TargetRef, ",")
		for _, kind := range kinds {
			if s.RedactActions[kind] != "block" {
				return errors.New("A category in this record is no longer set to block. Check your privacy settings")
			}
		}
		for _, kind := range kinds {
			delete(s.RedactActions, kind)
		}
		return nil
	})
}

// SetBuiltinActions serves the built-in settings editor. A stale editor
// cannot write settings for an engine that is no longer selected.
func SetBuiltinActions(actions map[string]string) error {
	return editBuiltinSettings(func(s *settings.Settings) error {
		s.RedactActions = actions
		return nil
	})
}
