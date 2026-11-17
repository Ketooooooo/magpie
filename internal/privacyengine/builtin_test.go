package privacyengine

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yetone/magpie/internal/gwmw"
	"github.com/yetone/magpie/internal/settings"
	"github.com/yetone/magpie/internal/testenv"
)

type masker string

func (m masker) JSON(b []byte) ([]byte, int)                              { return b, 0 }
func (m masker) Text(s string) (string, int)                              { return string(m) + s, 1 }
func (masker) Restore(s string, _ bool) string                            { return s }
func (masker) Writer(w http.ResponseWriter) (http.ResponseWriter, func()) { return w, func() {} }

// The last masker registered serves until it is removed; with none, a
// request masking is wanted for is refused (fail closed), and one it isn't
// wanted for goes as it is.
func TestMaskingFailsClosed(t *testing.T) {
	if m, err := builtinMasking(false); m != nil || err != nil {
		t.Fatalf("not wanted: %v %v", m, err)
	}
	if _, err := builtinMasking(true); err != ErrUnprotected {
		t.Fatalf("wanted, none served: %v", err)
	}
	r1 := registerBuiltin(masker("1"))
	defer r1()
	r2 := registerBuiltin(masker("2"))
	if m, err := builtinMasking(true); err != nil || m != masker("2") {
		t.Fatalf("stacked: %v %v", m, err)
	}
	r2()
	if m, err := builtinMasking(true); err != nil || m != masker("1") {
		t.Fatalf("after the last's removal: %v %v", m, err)
	}
}

// With no masker served, the refresh is asked once, and a masker it serves
// is used; another within a second isn't asked again, and is refused.
func TestServedRefreshesOnce(t *testing.T) {
	ResetBuiltinRefreshForTest()
	var asked atomic.Int32
	var remove func()
	stop := RefreshBuiltin(func() { asked.Add(1); remove = registerBuiltin(masker("r")) })
	defer stop()
	if m, ok := servedBuiltin(); !ok || m != masker("r") || asked.Load() != 1 {
		t.Fatalf("refreshed: %v %v asked %d", m, ok, asked.Load())
	}
	remove()
	if _, ok := servedBuiltin(); ok || asked.Load() != 1 {
		t.Fatalf("within a second: asked %d", asked.Load())
	}
	ResetBuiltinRefreshForTest()
	stop()
	if _, ok := servedBuiltin(); ok || asked.Load() != 1 {
		t.Fatalf("after stop: asked %d", asked.Load())
	}
}

var _ gwmw.Masker = masker("")

func TestMain(m *testing.M) { testenv.Main(m) }

func TestBuiltinSessionUsesPinnedPolicy(t *testing.T) {
	off := EnableBuiltin()
	defer off()
	before := settings.Settings{RedactPersonal: true, RedactModelOff: true}
	session, err := Begin(t.Context(), before, false)
	if err != nil || session == nil {
		t.Fatalf("begin: %v", err)
	}
	defer session.Close()
	if err := settings.Save(settings.Settings{PrivacyEngine: Disabled}); err != nil {
		t.Fatal(err)
	}
	const value = "test@privacy-boundary.internal"
	result, err := session.ProtectJSON([]byte(`{"messages":[{"role":"user","content":"` + value + `"}]}`))
	if err != nil || len(result.Hits) != 1 || strings.Contains(string(result.Body), value) {
		t.Fatalf("pinned session lost the original policy: %v %s", err, result.Body)
	}
	if restored := session.RestoreText(result.Hits[0].Placeholder); restored != value {
		t.Fatalf("the reply was not restored: %q", restored)
	}
	if next, err := Begin(t.Context(), settings.Load(), false); err != nil || next != nil {
		t.Fatalf("new request did not follow engine selection: %v", err)
	}
}
