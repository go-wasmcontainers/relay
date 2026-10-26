// SPDX-License-Identifier: BSD-3-Clause

//go:build flowmap

package server

import _ "embed"

// flowMapWasm is the page's WebAssembly, gzipped, built by
// `go run ./internal/buildflowmap`. It is about 5 MB, so it is not committed:
// release binaries are built with -tags flowmap; a plain `go install` serves
// the page without it and says so.
//
//go:embed flowmap/flowmap.wasm.gz
var flowMapWasm []byte

// FlowMapBuilt reports whether this binary carries the flow-map page.
const FlowMapBuilt = true
