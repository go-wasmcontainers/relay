// SPDX-License-Identifier: BSD-3-Clause

package driver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/go-wasmcontainers/relay/frame"
)

// DialWebSocket opens a session at url (wss://relay.example/v1/data) with a
// session token. The token travels as a WebSocket subprotocol, so it is
// checked before the upgrade and never appears in a URL. hc may be nil (in a
// browser, js/wasm, the browser's WebSocket is used and hc is ignored).
func DialWebSocket(ctx context.Context, url, token string, hc *http.Client) (*Session, error) {
	c, _, err := websocket.Dial(ctx, url, dialOptions(hc, []string{frame.Subprotocol, frame.BearerPrefix + token}))
	if err != nil {
		return nil, err
	}
	if c.Subprotocol() != frame.Subprotocol {
		c.CloseNow()
		return nil, errors.New("relay did not accept subprotocol " + frame.Subprotocol)
	}
	c.SetReadLimit(frame.MaxFrame)
	return Dial(ctx, &wsTransport{c: c})
}

type wsTransport struct{ c *websocket.Conn }

func (t *wsTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	typ, b, err := t.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, errors.New("text message on the data channel")
	}
	return b, nil
}

func (t *wsTransport) WriteMessage(ctx context.Context, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return t.c.Write(ctx, websocket.MessageBinary, b)
}

func (t *wsTransport) Close(reason string) error {
	if len(reason) > 120 {
		reason = reason[:120]
	}
	return t.c.Close(websocket.StatusNormalClosure, reason)
}
