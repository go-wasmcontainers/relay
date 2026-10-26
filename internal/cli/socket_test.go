// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A state directory whose admin.sock would not fit sun_path: serve says so,
// with the length and the limit, instead of "bind: invalid argument".
func TestAdminSocketTooLong(t *testing.T) {
	long := filepath.Join(shortDir(t), strings.Repeat("d", 120))
	st := "--state-dir=" + long
	mustRun(t, "init", st, "--name", "localhost", "--ip", "127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := run(t, ctx, "serve", st, "--listen", "127.0.0.1:0")
	if err == nil {
		t.Fatal("serve bound a socket path longer than sun_path")
	}
	limit := strconv.Itoa(sunPathSize(runtime.GOOS) - 1)
	if msg := err.Error(); !strings.Contains(msg, "admin socket path") || !strings.Contains(msg, limit) ||
		!strings.Contains(msg, "--admin-socket") || strings.Contains(msg, "invalid argument") {
		t.Fatalf("error: %v", err)
	}
	// The client says the same.
	if _, err := run(t, ctx, "class", "list", st); err == nil || !strings.Contains(err.Error(), "--admin-socket") {
		t.Fatalf("client: %v", err)
	}
}

// --admin-socket puts the socket elsewhere; serve and the client both use it,
// and it is 0600.
func TestAdminSocketFlag(t *testing.T) {
	long := filepath.Join(shortDir(t), strings.Repeat("d", 120))
	st := "--state-dir=" + long
	sock := "--admin-socket=" + filepath.Join(shortDir(t), "a.sock")
	mustRun(t, "init", st, "--name", "localhost", "--ip", "127.0.0.1")
	ready := make(chan string, 1)
	serveReady = ready
	defer func() { serveReady = nil }()
	ctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		_, err := run(t, ctx, "serve", st, sock, "--listen", "127.0.0.1:0")
		served <- err
	}()
	select {
	case <-ready:
	case err := <-served:
		t.Fatalf("serve: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not start")
	}
	defer func() { stop(); <-served }()
	if out := mustRun(t, "class", "create", "x", st, sock); !strings.Contains(out, "join code") {
		t.Fatal(out)
	}
	fi, err := os.Stat(strings.TrimPrefix(sock, "--admin-socket="))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket: %v %v", fi.Mode(), err)
	}
}

func TestSunPathSize(t *testing.T) {
	if sunPathSize("darwin") != 104 || sunPathSize("linux") != 108 || sunPathSize("freebsd") != 104 {
		t.Fatal("sun_path sizes")
	}
}
