// SPDX-License-Identifier: BSD-3-Clause

//go:build js && wasm

// Command wasm is the flow-map page's WebAssembly: it reads the page's
// configuration (class, ticket or session token, from the URL fragment, set
// by flowmap.js), streams FlowLogService.WatchFlowMap from the relay that
// served the page, and runs the scene on the canvas.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"syscall/js"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/go-widgets/toolkit"
	"github.com/go-widgets/webcanvas"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/web/flowmap"
)

type headers struct {
	base http.RoundTripper
	h    map[string]string
}

func (t headers) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range t.h {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}

func main() {
	cfg := js.Global().Get("wctrFlowmapConfig")
	classID := cfg.Get("classId").String()
	h := map[string]string{}
	if t := cfg.Get("ticket").String(); t != "" {
		h["Wctr-Map-Ticket"] = t
	}
	if t := cfg.Get("session").String(); t != "" {
		h["Wctr-Session"] = t
	}
	doc := js.Global().Get("document")
	status := doc.Call("getElementById", "status")
	canvas := doc.Call("getElementById", "screen")
	w, hgt := canvas.Get("clientWidth").Int(), canvas.Get("clientHeight").Int()

	// Anti-aliased text, legible on a projector (the bundled Atkinson
	// Hyperlegible face); the 5x7 bitmap stays the fallback.
	_ = toolkit.UseOpenTypeTextSize(13)
	scene := flowmap.NewScene(w, hgt)
	if js.Global().Call("matchMedia", "(prefers-color-scheme: dark)").Get("matches").Bool() {
		scene.Theme = toolkit.DefaultDark()
	}
	scene.OnChange = func() {
		status.Set("textContent", scene.VM.Status)
		b, _ := json.Marshal(scene.VM.Snapshot())
		js.Global().Set("wctrFlowmapState", string(b))
	}
	js.Global().Set("wctrFlowmapFilter", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) == 1 {
			scene.SetFilter(args[0].String())
		}
		return nil
	}))

	client := relayv1connect.NewFlowLogServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Transport: headers{base: http.DefaultTransport, h: h}}, cfg.Get("base").String())))
	go func() {
		for {
			stream, err := client.WatchFlowMap(context.Background(), &v1.WatchFlowMapRequest{ClassId: classID})
			if err == nil {
				for {
					u, err := stream.Receive()
					if err != nil {
						break
					}
					scene.Post(u)
				}
				stream.Close()
			} else {
				status.Set("textContent", "disconnected: "+err.Error())
			}
			time.Sleep(2 * time.Second)
		}
	}()
	webcanvas.Run("screen", scene)
}
