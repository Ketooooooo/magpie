package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/filelock"
	"github.com/yetone/magpie/internal/pii"
)

// The model, at a revision of LocalAI's repo, so the file is always the
// one hashed here.
var (
	modelURL  = "https://huggingface.co/LocalAI-io/privacy-filter-GGUF/resolve/935d86882f4b5dc6e0eef05aae48ae5ba0a82a7a/privacy-filter-q8.gguf"
	modelSize = int64(1637572192)
	modelSHA  = "80efc1803eda7c095a79741d2008c07e2e0a57b01bac8825fbeb448fd097998c"
)

// pf-serve, as the privacy-filter workflow built it at serveTag: a zip for
// each system, by its sha256. A system with none can't run the model.
// oldTags are the tags pinned before, newest first: one of theirs on disk
// is run until serveTag's is downloaded (upgrade).
var (
	serveTag  = "pf-v4"
	oldTags   = []string{"pf-v3", "pf-v2", "pf-v1"}
	serveBase = "https://github.com/yetone/magpie/releases/download/"
	serveSHA  = map[string]string{
		"darwin-amd64":  "dc287579abeafe0be0add35305bde05f9cb06405f6b98dda5d71c9bf2c53c2a0",
		"darwin-arm64":  "da4c89248937221a880996964e76a3dec18a9f8f80f2ee39e1cf26ef0933ac69",
		"linux-amd64":   "8a7e61e6deebde68b13fc17009c84aef9da2230ea9e696c9e62b32e79c30db00",
		"linux-arm64":   "0c29b9fdd1452f75414ee5fc623cfec70f4180af5046a9e669a289db7bf3da08",
		"windows-amd64": "4457116e76d5861b28f26fa15613a943a434d35174f30aa3b8488e76bccc6545",
	}
)

// Supported says pf-serve is built for this system.
func Supported() bool { return serveSHA[target()] != "" }

// Keep ownership separate from the built-in model so deleting the
// built-in's cache doesn't break the configured plugin.
var dir = func() string { return filepath.Join(appdir.Cache(), "privacy-filter-plugin") }

var builtInDir = func() string { return filepath.Join(appdir.Cache(), "privacy-filter") }

func modelPath() string { return filepath.Join(dir(), modelName()) }

// modelName is the model's file name in dir, ASCII alone: pf-serve is
// given this, not its full path.
func modelName() string { return "privacy-filter-q8-" + modelSHA[:12] + ".gguf" }

func serveDir() string { return tagDir(serveTag) }

func tagDir(tag string) string { return filepath.Join(dir(), tag+"-"+target()) }

// tagDirs are where tag's pf-serve may be on disk: tagDir, and under
// Rosetta also the Intel one's, which magpie fetched there before it
// fetched Apple silicon's (target).
func tagDirs(tag string) []string {
	ds := []string{tagDir(tag)}
	if osArch != target() {
		ds = append(ds, filepath.Join(dir(), tag+"-"+osArch))
	}
	return ds
}

// exe is a program of pf-serve's: serveTag's, or, until that is
// downloaded, the newest of oldTags' on disk.
func exe(name string) string { return exeIn(binDir(), name) }

func exeIn(d, name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(d, name)
}

func binDir() string {
	for _, tag := range append([]string{serveTag}, oldTags...) {
		for _, d := range tagDirs(tag) {
			if _, err := os.Stat(exeIn(d, "pf-serve")); err == nil {
				return d
			}
		}
	}
	return serveDir()
}

// install downloads the pinned helper and weights, or reuses a verified local model.
func install(ctx context.Context) error {
	if !Supported() {
		return fmt.Errorf("no pf-serve build for %s", target())
	}
	if err := os.MkdirAll(dir(), 0o755); err != nil {
		return err
	}
	unlock, held := filelock.Lock(filepath.Join(dir(), "install.lock"), filelock.Wait)
	if !held {
		return errors.New("could not lock the Privacy Filter installation")
	}
	defer unlock()
	if !available(exeIn(serveDir(), "pf-serve")) {
		if err := installServe(ctx); err != nil {
			return fmt.Errorf("install pf-serve: %w", err)
		}
	}
	if verifiedWeights(modelPath()) {
		return nil
	}
	existing, err := filepath.EvalSymlinks(filepath.Join(builtInDir(), modelName()))
	if err == nil && verifiedWeights(existing) && os.Link(existing, modelPath()) == nil {
		return nil
	}
	var done atomic.Int64
	return pii.Fetch(ctx, modelURL, modelPath(), modelSize, modelSHA, &done)
}

func verifiedWeights(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != modelSize {
		return false
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	return err == nil && hex.EncodeToString(hash.Sum(nil)) == modelSHA
}

// installServe fetches pf-serve's zip and puts what is in it in
// serveDir: each file by its name alone, so nothing lands outside it.
func installServe(ctx context.Context) error {
	z := filepath.Join(dir(), serveTag+"-"+target()+".zip")
	defer os.Remove(z)
	var n atomic.Int64
	if err := pii.Fetch(ctx, serveBase+serveTag+"/pf-serve-"+target()+".zip", z, -1, serveSHA[target()], &n); err != nil {
		return err
	}
	zr, err := zip.OpenReader(z)
	if err != nil {
		return err
	}
	defer zr.Close()
	tmp, err := os.MkdirTemp(dir(), serveTag+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if err := unzipTo(f, filepath.Join(tmp, filepath.Base(f.Name))); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(tmp, filepath.Base(exe("pf-serve")))); err != nil {
		return fmt.Errorf("the zip has no %s", filepath.Base(exe("pf-serve")))
	}
	return os.Rename(tmp, serveDir())
}

func unzipTo(f *zip.File, path string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
