package privacyengine

import (
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/privacyengine/internal/masking"
	"github.com/yetone/magpie/internal/privacyengine/internal/redact"
	"github.com/yetone/magpie/internal/settings"
)

var builtin struct {
	sync.Mutex
	stack      []*gwmw.Masker
	refresh    func()
	refreshing bool
	last       time.Time
}

var ErrUnprotected = errors.New("masking is on in magpie's Settings → Privacy, but the redact plugin isn't serving it, so nothing was sent; turn the plugin on in Settings → Plugins")

// EnableBuiltin serves the built-in engine for the lifetime of its plugin.
func EnableBuiltin() func() { return registerBuiltin(masking.Masker{}) }

func registerBuiltin(m gwmw.Masker) func() {
	builtin.Lock()
	builtin.stack = append(builtin.stack, &m)
	builtin.Unlock()
	return sync.OnceFunc(func() {
		builtin.Lock()
		defer builtin.Unlock()
		builtin.stack = slices.DeleteFunc(builtin.stack, func(entry *gwmw.Masker) bool { return entry == &m })
	})
}

// RefreshBuiltin lets the host refresh the built-in plugin on demand.
func RefreshBuiltin(refresh func()) func() {
	builtin.Lock()
	builtin.refresh = refresh
	builtin.Unlock()
	return sync.OnceFunc(func() {
		builtin.Lock()
		defer builtin.Unlock()
		builtin.refresh = nil
	})
}

func servedBuiltin() (gwmw.Masker, bool) {
	builtin.Lock()
	if n := len(builtin.stack); n > 0 {
		m := *builtin.stack[n-1]
		builtin.Unlock()
		return m, true
	}
	refresh := builtin.refresh
	if refresh == nil || builtin.refreshing || time.Since(builtin.last) < time.Second {
		builtin.Unlock()
		return nil, false
	}
	builtin.refreshing, builtin.last = true, time.Now()
	builtin.Unlock()
	defer func() {
		builtin.Lock()
		builtin.refreshing = false
		builtin.Unlock()
	}()
	refresh()
	builtin.Lock()
	defer builtin.Unlock()
	if n := len(builtin.stack); n > 0 {
		return *builtin.stack[n-1], true
	}
	return nil, false
}

func builtinMasking(wanted bool) (gwmw.Masker, error) {
	if !wanted {
		return nil, nil
	}
	if m, ok := servedBuiltin(); ok {
		return m, nil
	}
	return nil, ErrUnprotected
}

// InitBuiltin initializes the built-in engine's persistent mask key.
func InitBuiltin() { redact.SetKeyPath(filepath.Join(settings.Dir(), "redact.key")) }

// RegisterBuiltinForTest supplies a controlled engine in integration tests.
func RegisterBuiltinForTest(m gwmw.Masker) func() {
	if !testing.Testing() {
		panic("test-only privacy engine")
	}
	return registerBuiltin(m)
}

func ResetBuiltinRefreshForTest() {
	if !testing.Testing() {
		panic("test-only privacy refresh")
	}
	builtin.Lock()
	defer builtin.Unlock()
	builtin.last = time.Time{}
}

// BuiltinForTest supplies the native implementation to test doubles.
func BuiltinForTest() interface {
	gwmw.Masker
	gwmw.Teller
	gwmw.ContextTeller
} {
	if !testing.Testing() {
		panic("test-only privacy engine")
	}
	return masking.Masker{}
}
