// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/go-authn/oidc"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/server"
)

// idp is a minimal OpenID provider for tests: discovery and a JWKS on a
// loopback http server (go-authn/oidc allows cleartext on loopback only),
// and ES256 tokens it mints.
type idp struct {
	*httptest.Server
	key *ecdsa.PrivateKey
}

func newIDP(t *testing.T) *idp {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &idp{key: k}
	mux := http.NewServeMux()
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": p.URL, "jwks_uri": p.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b := func(x []byte) string { return base64.RawURLEncoding.EncodeToString(x) }
		pub := k.PublicKey
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "kid": "k1",
			"use": "sig", "alg": "ES256", "x": b(pad32(pub.X.Bytes())), "y": b(pad32(pub.Y.Bytes()))}}})
	})
	return p
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (p *idp) token(t *testing.T, aud, sub string, groups []string) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": "k1"})
	c, _ := json.Marshal(map[string]any{"iss": p.URL, "aud": aud, "sub": sub, "groups": groups,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + enc.EncodeToString(append(pad32(r.Bytes()), pad32(s.Bytes())...))
}

func TestOIDC(t *testing.T) {
	p := newIDP(t)
	v, err := oidc.New(tctx(t), oidc.Config{Issuer: p.URL, Audience: "relay"})
	if err != nil {
		t.Fatal(err)
	}
	g := newRig(t, server.Config{OIDC: v, TeacherGroup: "teachers"})
	ctx := tctx(t)

	// The teacher role, from the groups claim, on the admin listener only.
	teacher := withHeader(g.adm.Client(), "Authorization", "Bearer "+p.token(t, "relay", "prof", []string{"teachers"}))
	cls, err := classClient(teacher, g.adm.URL).CreateClass(ctx, &v1.CreateClassRequest{Name: "remote", RequireIdentity: true,
		Allowed: []string{"group:students"}})
	if err != nil {
		t.Fatalf("teacher via OIDC: %v", err)
	}
	notTeacher := withHeader(g.adm.Client(), "Authorization", "Bearer "+p.token(t, "relay", "stu", []string{"students"}))
	if _, err := classClient(notTeacher, g.adm.URL).ListClasses(ctx, &v1.ListClassesRequest{}); err == nil {
		t.Fatal("a student's token got the teacher role")
	}

	// Joining needs a valid identity on the class's list.
	join := func(tok string) error {
		c := g.public
		if tok != "" {
			c = withHeader(g.public, "Authorization", "Bearer "+tok)
		}
		_, err := joinClient(c, g.pub.URL).Join(ctx, &v1.JoinRequest{JoinCode: cls.JoinCode, DisplayName: "S"})
		return err
	}
	if err := join(""); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no token: %v", err)
	}
	if err := join(p.token(t, "other-service", "stu", []string{"students"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("token for another audience: %v", err)
	}
	if err := join(p.token(t, "relay", "visitor", nil)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("not on the list: %v", err)
	}
	if err := join(p.token(t, "relay", "stu", []string{"students"})); err != nil {
		t.Fatalf("student: %v", err)
	}
}
