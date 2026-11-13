package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/yetone/magpie/internal/netproxy"
)

// PrivacySpec declares an engine loaded by the existing Bun plugin host.
type PrivacySpec struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Entry    string `json:"entry"`
}

// Privacy reads a plugin's declaration without loading any of its code.
func Privacy(target string) (spec *PrivacySpec, only bool) {
	f, err := os.Open(filepath.Join(target, "package.json"))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var pkg struct {
		Main    string          `json:"main"`
		Exports json.RawMessage `json:"exports"`
		Magpie  struct {
			Privacy *PrivacySpec `json:"privacy"`
		} `json:"magpie"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 256<<10))
	if decoder.Decode(&pkg) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, false
	}
	s := pkg.Magpie.Privacy
	if s == nil || !actionID.MatchString(s.ID) || (s.ID == "magpie" || s.ID == "none") {
		return nil, false
	}
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" || len(s.Name) > 100 || strings.ContainsFunc(s.Name, unicode.IsControl) {
		return nil, false
	}
	if s.Protocol != "body-v1" || !fs.ValidPath(s.Entry) || !filepath.IsLocal(filepath.FromSlash(s.Entry)) ||
		!strings.HasSuffix(s.Entry, ".mjs") {
		return nil, false
	}
	return s, pkg.Main == "" && len(pkg.Exports) == 0
}

// PreviewPrivacy asks the installed engine for a read-only preview.
func PreviewPrivacy(ctx context.Context, target string, spec PrivacySpec, directory string, input, output any) error {
	params, err := privacyParams(target, spec, directory, input)
	if err != nil {
		return err
	}
	return Call(ctx, "privacyPreview", params, output)
}

// ApplyPrivacyRecordAction sends an action selected in a masking record to its engine.
func ApplyPrivacyRecordAction(ctx context.Context, target string, spec PrivacySpec, directory string, input any) error {
	params, err := privacyParams(target, spec, directory, input)
	if err != nil {
		return err
	}
	return Call(ctx, "privacyRecordAction", params, nil)
}

func privacyParams(target string, spec PrivacySpec, directory string, input any) (map[string]any, error) {
	root, err := os.OpenRoot(target)
	if err != nil {
		return nil, errors.New("The privacy plugin package is unavailable")
	}
	defer root.Close()
	file, err := root.Stat(filepath.FromSlash(spec.Entry))
	if err != nil || !file.Mode().IsRegular() {
		return nil, errors.New("The privacy plugin entry is unavailable")
	}
	return map[string]any{
		"entry":     filepath.Join(target, filepath.FromSlash(spec.Entry)),
		"directory": directory, "input": input,
	}, nil
}

// PrivacyStream carries a request and its reply bytes through one owned host call.
type PrivacyStream struct {
	body    *body
	decoder *json.Decoder
	ctx     context.Context
}

const privacyWindow = 128 << 10

func BeginPrivacyStream(ctx context.Context, target string, spec PrivacySpec, directory string, input, output any) (*PrivacyStream, error) {
	if err := netproxy.Held(ctx); err != nil {
		return nil, err
	}
	params, err := privacyParams(target, spec, directory, input)
	if err != nil {
		return nil, err
	}
	startup, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	h, err := get(startup)
	if err != nil {
		return nil, err
	}
	select {
	case h.privacyStreams <- struct{}{}:
	case <-startup.Done():
		return nil, startup.Err()
	case <-h.dead:
		return nil, errHostGone
	}
	id, c, err := h.admitCall(true, true, privacyWindow)
	if err != nil {
		return nil, err
	}
	c.watchCtx(ctx)
	params["window"] = privacyWindow
	err = h.enqueueCall(startup, map[string]any{"id": id, "method": "privacyBegin", "params": params}, nil, c)
	if err != nil {
		c.settle(err)
		return nil, err
	}
	b := &body{h: h, id: id, c: c, ctx: startup, closed: make(chan struct{})}
	s := &PrivacyStream{body: b, decoder: json.NewDecoder(b), ctx: ctx}
	if err := s.decoder.Decode(output); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *PrivacyStream) Reply(input, output any) error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	s.body.ctx = ctx
	if err := s.body.h.enqueueOwned(ctx, map[string]any{"method": "privacyReply", "params": map[string]any{"id": s.body.id, "chunk": input}}, nil, s.body.c, callActive); err != nil {
		return err
	}
	return s.decoder.Decode(output)
}

func (s *PrivacyStream) Close() { _ = s.body.Close() }
