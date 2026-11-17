package privacyengine

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/privacyengine/internal/masking"
	"github.com/yetone/magpie/internal/privacyengine/internal/redact"
	"github.com/yetone/magpie/internal/privacyengine/policy"
	"github.com/yetone/magpie/internal/settings"
)

func nativeEngine() engine {
	return engine{
		info:        Info{ID: Builtin, Name: "Magpie", Builtin: true},
		actions:     builtinActions{},
		recordValue: builtinRecordValue,
		wanted:      masking.Wanted,
		begin: func(ctx context.Context, st settings.Settings, forced bool) (context.Context, gwmw.Masker, error) {
			wanted := masking.Wanted(st)
			m, err := builtinMasking(forced || wanted)
			if forced && !wanted && err == nil {
				if _, ok := m.(gwmw.ContextTeller); !ok {
					return ctx, nil, ErrUnprotected
				}
				ctx = masking.WithForced(ctx)
			}
			return masking.WithSettings(ctx, st), m, err
		},
		preview: func(_ context.Context, input string) (string, []gwmw.Hit, bool, error) {
			text, hits, off := masking.Preview(input)
			return text, hits, off, nil
		},
	}
}

// WithRoute supplies the set of destinations when the built-in engine reuses a prefix.
func WithRoute(ctx context.Context, route string) context.Context {
	return masking.WithRoute(ctx, route)
}

func BuiltinFingerprint(st settings.Settings) string { return masking.Fingerprint(st) }

func BuiltinModelWanted(st settings.Settings) bool { return masking.ModelWanted(st) }
func BuiltinModelOn() bool                         { return ID(settings.Shared()) == Builtin && masking.ModelOn() }
func BuiltinModelBusy() string                     { return masking.ModelBusy() }

// DiagnosticCopy applies the local built-in policy to content shown in Magpie.
func DiagnosticCopy(ctx context.Context, st settings.Settings, body []byte) []byte {
	if ID(st) != Disabled {
		st.PrivacyEngine = Builtin
	}
	session, err := Begin(ctx, st, false)
	if err != nil {
		return nil
	}
	if session == nil {
		return body
	}
	defer session.Close()
	out, err := session.ProtectJSON(body)
	if err != nil {
		return nil
	}
	return out.Body
}

// HasBuiltinPlaceholder recognizes the built-in engine's format for its model note.
func HasBuiltinPlaceholder(text string) bool { return redact.HasPlaceholder(text) }

var ErrBuiltinSettings = errors.New("These settings belong to the built-in privacy engine")

func editBuiltinSettings(edit func(*settings.Settings) error) error {
	return settings.EditBuiltinPrivacy(func(s *settings.Settings) error {
		if ID(*s) != Builtin {
			return ErrBuiltinSettings
		}
		return edit(s)
	})
}

func SetBuiltinRules(rules []policy.Rule) error {
	return editBuiltinSettings(func(s *settings.Settings) error {
		s.RedactRules = rules
		return nil
	})
}

func SetBuiltinAllow(allow []string) error {
	return editBuiltinSettings(func(s *settings.Settings) error {
		s.RedactAllow = allow
		return nil
	})
}

func UpdateBuiltinRule(at int, was, to policy.Rule) error {
	return editBuiltinSettings(func(s *settings.Settings) error {
		next, err := editRedactRule(s.RedactRules, at, was, to)
		if err == nil {
			s.RedactRules = next
		}
		return err
	})
}

// editRedactRule is rules with the one at at, which must still be was,
// changed to to: tidied and checked as an added rule is, in the same place.
// It is refused when that rule is no longer there (changed or removed
// meanwhile), when to has neither a prefix nor a pattern (taking a rule
// away is Remove), and when to is another rule already listed.
func editRedactRule(rules []policy.Rule, at int, was, to policy.Rule) ([]policy.Rule, error) {
	if at < 0 || at >= len(rules) || rules[at] != was {
		return nil, fmt.Errorf("that masking rule is no longer there: it was changed or removed meanwhile")
	}
	tidy, err := redact.CheckRules([]redact.Rule{to})
	if err != nil {
		return nil, err
	}
	if len(tidy) == 0 {
		return nil, fmt.Errorf("a masking rule needs a prefix or a regular expression")
	}
	for i, o := range rules {
		if i != at && o == tidy[0] {
			return nil, fmt.Errorf("the masking rule %s is there already", o.Kind)
		}
	}
	next := slices.Clone(rules)
	next[at] = tidy[0]
	return next, nil
}
