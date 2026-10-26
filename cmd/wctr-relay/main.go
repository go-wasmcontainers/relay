// SPDX-License-Identifier: BSD-3-Clause

// Command wctr-relay is the classroom relay and firewall for WASI containers:
// `wctr-relay serve` runs it, the other commands manage it.
package main

import (
	"os"

	"github.com/go-wasmcontainers/relay/internal/cli"
)

// osExit is replaced by tests.
var osExit = os.Exit

func main() {
	osExit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
