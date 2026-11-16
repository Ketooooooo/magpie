// magpie — one place to pick every agent's model. The commands live in
// internal/cli; this is only where the binary starts.
package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/yetone/magpie/internal/cli"
	"github.com/yetone/magpie/internal/notices"
	"github.com/yetone/magpie/internal/pii"
	// the built-in plugins, registered with the runtime (internal/pluginrt)
	_ "github.com/yetone/magpie/plugins/all"
)

// version is set at build time: -ldflags "-X main.version=…" (Makefile,
// Dockerfile, magpie-releases), so it stays in package main.
var version = "dev"

// the notices of what is compiled into every build (moejs's Intl data and
// code), carried by the binary itself, since most release assets are a
// bare binary
//
//go:embed THIRD_PARTY_NOTICES
var thirdParty string

func main() {
	if len(os.Args) == 3 && os.Args[1] == pii.AstrLinkServeCommand {
		if err := pii.ServeAstrLink(os.Args[2], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	notices.Text = thirdParty
	cli.Main(version)
}
