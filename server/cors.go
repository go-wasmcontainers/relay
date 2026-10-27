// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	connectcors "connectrpc.com/cors"
)

// CORS on the public listener: a page served from another origin (the
// playground on GitHub Pages) calls Join, RefreshSession and the flow map
// from the browser. Only origins in the relay's allowlist may, never "*";
// credentials mode is never enabled (tokens travel in headers, not cookies).
// The admin listener has no CORS at all.

// corsPaths are the RPCs a cross-origin page may call.
var corsPaths = []string{
	"/wasmcontainers.relay.v1.JoinService/Join",
	"/wasmcontainers.relay.v1.JoinService/RefreshSession",
	"/wasmcontainers.relay.v1.FlowLogService/WatchFlowMap",
	"/wasmcontainers.relay.v1.FlowLogService/WatchFlows",
	"/wasmcontainers.relay.v1.PortService/ListPorts",
}

// corsMaxAge bounds how long a browser caches a preflight (Chromium caps it
// at 7200 seconds anyway).
const corsMaxAge = 7200

// corsAllowedHeaders: what connect-go's clients send (connectrpc.com/cors
// AllowedHeaders), the relay's own credential headers, and User-Agent, which
// Firefox lists in the preflight when a Connect-Web client sets it.
func corsAllowedHeaders() []string {
	h := connectcors.AllowedHeaders()
	return append(h, "Authorization", sessionHeader, mapTicketHeader, "User-Agent")
}

// NormalizeOrigin checks an allowlist entry: scheme://host[:port], http or
// https, nothing else (no path, no wildcard).
func NormalizeOrigin(o string) (string, error) {
	if o == "*" || strings.Contains(o, "*") {
		return "", errors.New("a wildcard origin is refused: list the origins")
	}
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("origin %q: want scheme://host[:port], e.g. https://go-wasmcontainers.github.io", o)
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// originAllowed reports whether a request's Origin header is in the
// allowlist or is the relay's own origin (the Host it was reached at).
func (s *Server) originAllowed(r *http.Request, origin string) bool {
	o := strings.ToLower(origin)
	if slices.Contains(s.origins, o) {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

// cors wraps the public handler.
func (s *Server) cors(h http.Handler) http.Handler {
	allowHeaders := strings.Join(corsAllowedHeaders(), ", ")
	allowMethods := strings.Join(connectcors.AllowedMethods(), ", ")
	expose := strings.Join(connectcors.ExposedHeaders(), ", ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		ok := slices.Contains(corsPaths, r.URL.Path) && s.originAllowed(r, origin)
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			if !ok || !slices.Contains(connectcors.AllowedMethods(), r.Header.Get("Access-Control-Request-Method")) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			hd := w.Header()
			hd.Set("Access-Control-Allow-Origin", origin)
			hd.Set("Access-Control-Allow-Methods", allowMethods)
			hd.Set("Access-Control-Allow-Headers", allowHeaders)
			hd.Set("Access-Control-Max-Age", strconv.Itoa(corsMaxAge))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Expose-Headers", expose)
		}
		h.ServeHTTP(w, r)
	})
}
