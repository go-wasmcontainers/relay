// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package driver

import (
	"net/http"

	"github.com/coder/websocket"
)

func dialOptions(hc *http.Client, protos []string) *websocket.DialOptions {
	return &websocket.DialOptions{HTTPClient: hc, Subprotocols: protos}
}
