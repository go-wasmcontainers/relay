// SPDX-License-Identifier: BSD-3-Clause

// Package statedir lays out the relay's state directory: the control-plane
// state, the admin token, the session-token signing keys, the internal CA,
// the audit log and the admin socket. Every secret in it is a 0600 file of
// the relay's user, in a 0700 directory.
package statedir

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
)

// Dir is a state directory.
type Dir string

// Default is $XDG_CONFIG_HOME/wctr-relay (os.UserConfigDir()).
func Default() (Dir, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return Dir(filepath.Join(base, "wctr-relay")), nil
}

func (d Dir) path(n string) string { return filepath.Join(string(d), n) }

// State is the control-plane file.
func (d Dir) State() string { return d.path("state.json") }

// Socket is the admin socket.
func (d Dir) Socket() string { return d.path("admin.sock") }

// CA is the internal CA's directory.
func (d Dir) CA() string { return d.path("ca") }

// TokenFile holds the admin token.
func (d Dir) TokenFile() string { return d.path("admin.token") }

// AuditLog is the audit log.
func (d Dir) AuditLog() string { return d.path("audit.log") }

func (d Dir) keysFile() string { return d.path("keys.json") }

// Ensure creates the directory 0700, or checks an existing one is not open
// to group or others.
func (d Dir) Ensure() error {
	if err := os.MkdirAll(string(d), 0o700); err != nil {
		return err
	}
	st, err := os.Stat(string(d))
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %v: it holds secrets, it must be 0700", d, st.Mode().Perm())
	}
	return nil
}

// Init creates the admin token and the signing keys if they are missing.
func (d Dir) Init() (created bool, err error) {
	if err := d.Ensure(); err != nil {
		return false, err
	}
	if _, err := os.Stat(d.TokenFile()); errors.Is(err, os.ErrNotExist) {
		tok, err := auth.RandomToken()
		if err != nil {
			return false, err
		}
		if err := writeSecret(d.TokenFile(), []byte(tok+"\n")); err != nil {
			return false, err
		}
		created = true
	}
	if _, err := os.Stat(d.keysFile()); errors.Is(err, os.ErrNotExist) {
		k, err := auth.NewKeys()
		if err != nil {
			return false, err
		}
		if err := d.saveKeys(k); err != nil {
			return false, err
		}
		created = true
	}
	return created, nil
}

func writeSecret(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadSecret reads a 0600 file of the caller's, trimmed.
func ReadSecret(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s has mode %v: a secret must be 0600", path, st.Mode().Perm())
	}
	if st.Size() > 64<<10 {
		return "", fmt.Errorf("%s is larger than 64 KiB", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(b)), nil
}

// AdminToken reads the admin token.
func (d Dir) AdminToken() (string, error) { return ReadSecret(d.TokenFile()) }

type keysJSON struct {
	Current uint8             `json:"current"`
	Seeds   map[string]string `json:"seeds"` // key id -> base64 Ed25519 seed
}

func (d Dir) saveKeys(k *auth.Keys) error {
	j := keysJSON{Current: k.Current, Seeds: map[string]string{}}
	for id, priv := range k.Private {
		j.Seeds[strconv.Itoa(int(id))] = base64.StdEncoding.EncodeToString(priv.Seed())
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeSecret(d.keysFile(), b)
}

// Keys reads the session-token signing keys.
func (d Dir) Keys() (*auth.Keys, error) {
	s, err := ReadSecret(d.keysFile())
	if err != nil {
		return nil, err
	}
	var j keysJSON
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		return nil, fmt.Errorf("%s: %w", d.keysFile(), err)
	}
	k := &auth.Keys{Current: j.Current, Private: map[uint8]ed25519.PrivateKey{}}
	for id, seed := range j.Seeds {
		n, err := strconv.Atoi(id)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("%s: key id %q", d.keysFile(), id)
		}
		b, err := base64.StdEncoding.DecodeString(seed)
		if err != nil || len(b) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: key %s", d.keysFile(), id)
		}
		k.Private[uint8(n)] = ed25519.NewKeyFromSeed(b)
	}
	if _, ok := k.Private[k.Current]; !ok {
		return nil, fmt.Errorf("%s: no current key", d.keysFile())
	}
	return k, nil
}

// Audit is an append-only JSON-lines log, 0600.
type Audit struct {
	mu sync.Mutex
	f  *os.File
}

// OpenAudit opens the audit log, first dropping lines older than keep.
func (d Dir) OpenAudit(keep time.Duration, now time.Time) (*Audit, error) {
	path := d.AuditLog()
	if b, err := os.ReadFile(path); err == nil && keep > 0 {
		var kept bytes.Buffer
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		cut := now.Add(-keep)
		for sc.Scan() {
			var line struct {
				Time time.Time `json:"time"`
			}
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Time.Before(cut) {
				continue
			}
			kept.Write(sc.Bytes())
			kept.WriteByte('\n')
		}
		tmp := path + ".tmp"
		os.Remove(tmp)
		if err := writeSecret(tmp, kept.Bytes()); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Audit{f: f}, nil
}

// Write appends one event.
func (a *Audit) Write(event string, fields map[string]string) {
	m := map[string]any{"time": time.Now().UTC(), "event": event}
	for k, v := range fields {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.f.Write(append(b, '\n'))
}

// Close closes the log.
func (a *Audit) Close() error { return a.f.Close() }
