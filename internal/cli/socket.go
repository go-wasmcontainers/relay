// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
)

// sunPathSize is sizeof(sockaddr_un.sun_path) on this system: 104 bytes on
// macOS and the BSDs, 108 on Linux (and Windows' AF_UNIX). A path must fit
// with its terminating NUL, so the longest usable path is one byte less.
func sunPathSize(goos string) int {
	switch goos {
	case "darwin", "ios", "freebsd", "netbsd", "openbsd", "dragonfly":
		return 104
	}
	return 108
}

// checkSocketPath refuses a Unix socket path the system cannot bind, with
// the reason, instead of the kernel's bare "bind: invalid argument".
func checkSocketPath(p string) error {
	size := sunPathSize(runtime.GOOS)
	if len(p) > size-1 {
		return fmt.Errorf("admin socket path %s is %d bytes; a Unix socket path holds at most %d on %s "+
			"(sun_path is %d bytes): choose a shorter one with --admin-socket", p, len(p), size-1, runtime.GOOS, size)
	}
	return nil
}

// adminSocket is the admin socket's path: --admin-socket, or admin.sock in
// the state directory.
func (g *globals) adminSocket() (string, error) {
	p := g.adminSock
	if p == "" {
		d, err := g.dir()
		if err != nil {
			return "", err
		}
		p = d.Socket()
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return abs, checkSocketPath(abs)
}

// listenAdmin binds the admin socket 0600 without a window in which another
// user could connect: it is bound inside a fresh 0700 directory, made 0600,
// then renamed into place. A stale socket at the path is replaced.
func listenAdmin(p string) (net.Listener, error) {
	tmp, err := os.MkdirTemp(filepath.Dir(p), ".wr")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	staging := filepath.Join(tmp, "s")
	if err := checkSocketPath(staging); err != nil {
		return nil, fmt.Errorf("staging the admin socket: %w", err)
	}
	l, err := net.Listen("unix", staging)
	if err != nil {
		return nil, err
	}
	// The listener must not unlink the path it was bound at when it closes:
	// that path is renamed away below.
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(staging, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	os.Remove(p)
	if err := os.Rename(staging, p); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
