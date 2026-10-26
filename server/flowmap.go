// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
)

var _ relayv1connect.FlowMapServiceHandler = (*services)(nil)

// FlowMapTicket issues a read-only ticket for the teacher's flow-map page.
func (sv *services) FlowMapTicket(ctx context.Context, r *v1.FlowMapTicketRequest) (*v1.FlowMapTicketResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	tok, exp, err := sv.s.cfg.Relay.MapTicket(r.ClassId)
	if err != nil {
		return nil, cerr(err)
	}
	return &v1.FlowMapTicketResponse{Ticket: tok, ExpiresUnix: exp.Unix()}, nil
}

// WatchFlowMap streams the flow map: the whole class for the teacher (admin
// or a map ticket), one session's flows for a student.
func (sv *services) WatchFlowMap(ctx context.Context, r *v1.WatchFlowMapRequest, out relayv1connect.FlowLogServiceWatchFlowMapServerStream) error {
	p := principal(ctx)
	session := ""
	switch {
	case p.Admin:
	case p.MapClass != "" && p.MapClass == r.ClassId:
	case p.Session != nil && p.Session.Class == r.ClassId:
		session = p.Session.Session
	case p.Session == nil && p.MapClass == "":
		return errUnauth
	default:
		return errDenied
	}
	tick := time.Duration(r.TickMs) * time.Millisecond
	if tick == 0 {
		tick = 250 * time.Millisecond
	}
	tick = min(max(tick, 100*time.Millisecond), 5*time.Second)
	w, err := sv.s.cfg.Relay.WatchMap(r.ClassId, session)
	if err != nil {
		return cerr(err)
	}
	defer w.Close()
	if err := out.SendHeaders(); err != nil {
		return err
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		u, err := w.Next(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return cerr(err)
		}
		// Send blocks while the reader is slow: the next update is built
		// only after it, from the state of that moment (coalesced).
		if err := out.Send(u); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.Done():
			return nil
		case <-t.C:
		}
	}
}

//go:embed flowmap/index.html flowmap/flowmap.css flowmap/flowmap.js flowmap/wasm_exec.js
var flowMapFiles embed.FS

// flowMapCSP: same origin only; WebAssembly compilation is the one
// allowance the page needs ('wasm-unsafe-eval', narrower than 'unsafe-eval').
const flowMapCSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; " +
	"style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// flowMapPage serves the page's static files under /flowmap/.
func flowMapPage() http.Handler {
	sub, err := fs.Sub(flowMapFiles, "flowmap")
	if err != nil {
		panic(err) // the embedded tree is part of the binary
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", flowMapCSP)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-cache")
		name := strings.TrimPrefix(r.URL.Path, "/flowmap/")
		if name == "flowmap.wasm" {
			if len(flowMapWasm) == 0 {
				http.Error(w, "this wctr-relay was built without the flow map (build tag flowmap)", http.StatusNotFound)
				return
			}
			// Stored gzipped; every browser that runs WebAssembly accepts it.
			h.Set("Content-Type", "application/wasm")
			h.Set("Content-Encoding", "gzip")
			_, _ = w.Write(flowMapWasm)
			return
		}
		if strings.HasSuffix(name, ".gz") {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + name
		files.ServeHTTP(w, r2)
	})
}
