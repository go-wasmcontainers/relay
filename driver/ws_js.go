// SPDX-License-Identifier: BSD-3-Clause

//go:build js

package driver

import (
	"net/http"

	"github.com/coder/websocket"
)

// In a browser the page's WebSocket does the handshake: no HTTP client.
func dialOptions(_ *http.Client, protos []string) *websocket.DialOptions {
	return &websocket.DialOptions{Subprotocols: protos}
}
