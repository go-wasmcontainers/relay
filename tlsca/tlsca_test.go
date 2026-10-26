// SPDX-License-Identifier: BSD-3-Clause

package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssueAndVerify(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, []string{"relay.class.example"}, []netip.Addr{netip.MustParseAddr("192.168.1.10")}); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, []string{"x"}, nil); err == nil {
		t.Fatal("Init overwrote a CA")
	}
	ca, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"relay.class.example", "192.168.1.10"} {
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: ca.Pool()}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "bank.example", Roots: ca.Pool()}); err == nil {
		t.Fatal("leaf verified for another name")
	}
	if leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore) > LeafLifetime+time.Hour {
		t.Fatal("leaf too long")
	}
	again, _ := ca.Leaf()
	if again != leaf {
		t.Fatal("leaf not cached")
	}
	if len(ca.Fingerprint()) != 64 || len(ca.RootPEM()) == 0 {
		t.Fatal("fingerprint/PEM")
	}
}

// The name constraints hold even for whoever holds the key: a certificate
// the CA signs for another site does not verify.
func TestNameConstraintsBindTheKey(t *testing.T) {
	dir := t.TempDir()
	Init(dir, []string{"relay.class.example"}, nil)
	ca, _ := Load(dir)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "evil"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"accounts.example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	evil, _ := x509.ParseCertificate(der)
	if _, err := evil.Verify(x509.VerifyOptions{DNSName: "accounts.example.com", Roots: ca.Pool()}); err == nil {
		t.Fatal("a stolen CA key signed for another site")
	}
}

func TestKeyMode(t *testing.T) {
	dir := t.TempDir()
	Init(dir, []string{"r.example"}, nil)
	if err := os.Chmod(filepath.Join(dir, keyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("loaded a world-readable key")
	}
}

func TestRotate(t *testing.T) {
	dir := t.TempDir()
	Init(dir, []string{"r.example"}, nil)
	a, _ := Load(dir)
	if err := Rotate(dir, []string{"r.example"}, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := Load(dir)
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("rotation kept the root")
	}
	if err := Init(t.TempDir(), nil, nil); err == nil {
		t.Fatal("a CA for nothing")
	}
}
