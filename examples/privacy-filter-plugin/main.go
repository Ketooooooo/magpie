package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	switch {
	case len(args) == 1 && args[0] == "install":
		if err := install(ctx); err != nil {
			return err
		}
		return writeOptions(os.Stdout)
	case len(args) == 1 && args[0] == "options":
		return writeOptions(os.Stdout)
	case len(args) == 2 && args[0] == "serve":
		return serve(ctx, args[1], os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("usage: magpie-pf install | options | serve <model.gguf>")
	}
}

// writeOptions emits the options the Magpie plugin installer accepts.
func writeOptions(w io.Writer) error {
	return json.NewEncoder(w).Encode(map[string]any{"models": []map[string]any{{
		"id": "q8", "name": "OpenAI Privacy Filter (plugin)", "path": modelPath(), "minScore": 0.5,
	}}})
}
