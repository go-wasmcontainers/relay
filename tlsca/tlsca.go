// SPDX-License-Identifier: BSD-3-Clause

// Package tlsca is the relay's internal CA, for a classroom with no public
// name: a root (ECDSA P-256) that a school installs on its machines,
// NAME-CONSTRAINED to the relay's names and addresses, so that even a stolen
// key cannot sign for any other site; and short leaf certificates issued
// from it on demand.
//
// The key is kept 0600 by its owner and never exported. Rotate makes a new
// root; machines must then trust the new one.
package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	rootFile = "ca.crt"
	keyFile  = "ca.key"
	// RootLifetime is the root's validity.
	RootLifetime = 2 * 365 * 24 * time.Hour
	// LeafLifetime is a server certificate's validity; renewed at half.
	LeafLifetime = 7 * 24 * time.Hour
)

// CA is a loaded internal CA.
type CA struct {
	root  *x509.Certificate
	key   *ecdsa.PrivateKey
	names []string
	ips   []netip.Addr
	now   func() time.Time

	mu   sync.Mutex
	leaf *tls.Certificate
}

// Init creates a CA in dir for these names and addresses. It refuses to
// overwrite one.
func Init(dir string, names []string, ips []netip.Addr) error {
	if len(names) == 0 && len(ips) == 0 {
		return errors.New("tlsca: at least one name or address")
	}
	if _, err := os.Stat(filepath.Join(dir, keyFile)); err == nil {
		return errors.New("tlsca: a CA exists in " + dir + " (rotate it instead)")
	}
	return write(dir, names, ips, time.Now())
}

// Rotate replaces the CA in dir with a new one.
func Rotate(dir string, names []string, ips []netip.Addr) error {
	return write(dir, names, ips, time.Now())
}

func write(dir string, names []string, ips []netip.Addr, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wctr-relay classroom CA", Organization: []string{"go-wasmcontainers"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(RootLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		// The CA can sign for these names and addresses only.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         names,
	}
	for _, ip := range ips {
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(ip.BitLen(), ip.BitLen())})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, keyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, rootFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads the CA in dir. The key file must not be readable by group or
// others.
func Load(dir string) (*CA, error) {
	kp := filepath.Join(dir, keyFile)
	st, err := os.Stat(kp)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("tlsca: %s has mode %v; it must be 0600", kp, st.Mode().Perm())
	}
	kb, err := os.ReadFile(kp)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(kb)
	if blk == nil {
		return nil, errors.New("tlsca: no PEM key in " + kp)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("tlsca: the CA key is not ECDSA")
	}
	cb, err := os.ReadFile(filepath.Join(dir, rootFile))
	if err != nil {
		return nil, err
	}
	cblk, _ := pem.Decode(cb)
	if cblk == nil {
		return nil, errors.New("tlsca: no PEM certificate in " + rootFile)
	}
	root, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	ca := &CA{root: root, key: key, names: root.PermittedDNSDomains, now: time.Now}
	for _, n := range root.PermittedIPRanges {
		if a, ok := netip.AddrFromSlice(n.IP); ok {
			ca.ips = append(ca.ips, a.Unmap())
		}
	}
	return ca, nil
}

// RootPEM is the root certificate a school installs.
func (ca *CA) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})
}

// Fingerprint is the root's SHA-256, for a person comparing it.
func (ca *CA) Fingerprint() string {
	h := sha256.Sum256(ca.root.Raw)
	return hex.EncodeToString(h[:])
}

// Pool trusts the root, for clients and tests.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.root)
	return p
}

// TLSConfig serves a leaf issued from the CA, renewed at half its life.
func (ca *CA) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return ca.Leaf()
	}}
}

// Leaf returns the current server certificate, issuing one if needed.
func (ca *CA) Leaf() (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.now()
	if ca.leaf != nil && now.Before(ca.leaf.Leaf.NotAfter.Add(-LeafLifetime/2)) {
		return ca.leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(LeafLifetime)
	if notAfter.After(ca.root.NotAfter) {
		notAfter = ca.root.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "wctr-relay"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     ca.names,
	}
	for _, ip := range ca.ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip.AsSlice())
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca.leaf = &tls.Certificate{Certificate: [][]byte{der, ca.root.Raw}, PrivateKey: key, Leaf: leaf}
	return ca.leaf, nil
}
