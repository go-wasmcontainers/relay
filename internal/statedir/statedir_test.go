// SPDX-License-Identifier: BSD-3-Clause

package statedir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
)

func TestInitAndKeys(t *testing.T) {
	d := Dir(filepath.Join(t.TempDir(), "s"))
	created, err := d.Init()
	if err != nil || !created {
		t.Fatal(created, err)
	}
	again, err := d.Init()
	if err != nil || again {
		t.Fatal("Init replaced existing secrets", again, err)
	}
	tok, err := d.AdminToken()
	if err != nil || len(tok) != 43 {
		t.Fatal(tok, err)
	}
	k, err := d.Keys()
	if err != nil {
		t.Fatal(err)
	}
	// A token signed before a restart verifies after it.
	signed, _ := k.Sign(auth.Claims{Expiry: time.Now().Add(time.Hour), Class: "c", Session: "s"})
	k2, _ := d.Keys()
	if _, err := k2.Verify(signed, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{d.TokenFile(), d.keysFile()} {
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v", f, st.Mode())
		}
	}
}

func TestRefusesOpenSecrets(t *testing.T) {
	d := Dir(filepath.Join(t.TempDir(), "s"))
	d.Init()
	os.Chmod(d.TokenFile(), 0o644)
	if _, err := d.AdminToken(); err == nil {
		t.Fatal("read a world-readable token")
	}
	os.Chmod(string(d), 0o755)
	if err := d.Ensure(); err == nil {
		t.Fatal("accepted a 0755 state directory")
	}
}

func TestAuditRetention(t *testing.T) {
	d := Dir(filepath.Join(t.TempDir(), "s"))
	d.Ensure()
	old := `{"time":"2020-01-01T00:00:00Z","event":"old"}` + "\n"
	os.WriteFile(d.AuditLog(), []byte(old), 0o600)
	a, err := d.OpenAudit(24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a.Write("rule.create", map[string]string{"rule": "r-1"})
	a.Close()
	b, _ := os.ReadFile(d.AuditLog())
	if strings.Contains(string(b), `"old"`) || !strings.Contains(string(b), "rule.create") {
		t.Fatalf("%s", b)
	}
	if st, _ := os.Stat(d.AuditLog()); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
}
