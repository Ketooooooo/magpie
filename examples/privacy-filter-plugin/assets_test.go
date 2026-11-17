package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestInstallPinsAssetsAndReusesTheCache(t *testing.T) {
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	f, err := z.Create("bin/" + exeIn("", "pf-serve"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("fake native helper")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}

	model := []byte("fake GGUF weights")
	var downloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		switch r.URL.Path {
		case "/" + serveTag + "/pf-serve-" + target() + ".zip":
			w.Write(archive.Bytes())
		case "/weights":
			w.Write(model)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	prevDir, prevBase, prevSHA := dir, serveBase, serveSHA
	prevURL, prevModelSHA, prevSize := modelURL, modelSHA, modelSize
	t.Cleanup(func() {
		dir, serveBase, serveSHA = prevDir, prevBase, prevSHA
		modelURL, modelSHA, modelSize = prevURL, prevModelSHA, prevSize
	})
	root := t.TempDir()
	dir = func() string { return root }
	serveBase = srv.URL + "/"
	serveSHA = map[string]string{target(): fmt.Sprintf("%x", sha256.Sum256(archive.Bytes()))}
	modelURL, modelSize = srv.URL+"/weights", int64(len(model))
	modelSHA = fmt.Sprintf("%x", sha256.Sum256(model))

	if err := install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(exe("pf-serve")); err != nil || string(got) != "fake native helper" || !verifiedWeights(modelPath()) {
		t.Fatalf("invalid cached assets: %q, %v", got, err)
	}
	if err := install(context.Background()); err != nil || downloads.Load() != 2 {
		t.Fatalf("install fetched existing assets again: %d requests, %v", downloads.Load(), err)
	}

	if err := os.WriteFile(modelPath(), bytes.Repeat([]byte("x"), len(model)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := install(context.Background()); err != nil || downloads.Load() != 3 || !verifiedWeights(modelPath()) {
		t.Fatalf("a same-size corrupt model was not replaced: %d requests, %v", downloads.Load(), err)
	}
}
