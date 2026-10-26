// SPDX-License-Identifier: BSD-3-Clause

//go:build !flowmap

package server

// flowMapWasm is empty in a build without the flowmap tag (see
// flowmap_wasm.go): /flowmap/flowmap.wasm then answers 404 with a reason.
var flowMapWasm []byte

// FlowMapBuilt reports whether this binary carries the flow-map page.
const FlowMapBuilt = false
