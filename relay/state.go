// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// State is the relay's control plane: everything that must survive a
// restart (and, in the high-availability design, everything a cluster
// replicates). Live flows and connection tracking are the data plane and are
// never in it: they are reset on a restart or a failover.
type State struct {
	Version int                `json:"version"`
	RelayID string             `json:"relay_id"`
	Classes map[string]*sClass `json:"classes"`
}

type sClass struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	JoinCode    string             `json:"join_code"`
	CIDR        string             `json:"cidr"`
	SessionBits int                `json:"session_bits"`
	DNSDomain   string             `json:"dns_domain"`
	Template    int                `json:"template"`
	Allowed     []string           `json:"allowed,omitempty"`
	RequireID   bool               `json:"require_identity,omitempty"`
	Created     int64              `json:"created"`
	Epoch       uint64             `json:"epoch"`
	DefaultSG   string             `json:"default_sg"`
	Groups      map[string]*sGroup `json:"groups"`
	Sessions    map[string]*sSess  `json:"sessions"`
	Ports       map[string]*sPort  `json:"ports"` // by port id
	NextID      uint64             `json:"next_id"`
}

type sGroup struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Stateful    bool    `json:"stateful"`
	Rules       []sRule `json:"rules"`
}

type sRule struct {
	ID           string `json:"id"`
	Direction    uint8  `json:"direction"`
	Protocol     uint8  `json:"protocol"`
	PortMin      uint16 `json:"port_min,omitempty"`
	PortMax      uint16 `json:"port_max,omitempty"`
	RemotePrefix string `json:"remote_ip_prefix,omitempty"`
	RemoteGroup  string `json:"remote_group_id,omitempty"`
	Description  string `json:"description,omitempty"`
	Log          bool   `json:"log,omitempty"`
}

type sSess struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Display  string `json:"display"`
	Index    int    `json:"index"` // subnet number within the class network
	Teacher  bool   `json:"teacher,omitempty"`
	Identity string `json:"identity,omitempty"` // sha256(iss NUL sub), hex: pseudonymous
	Created  int64  `json:"created"`
}

// A port survives its container's restarts and its browser's reconnects:
// same container name in the same session, same address.
type sPort struct {
	ID           string   `json:"id"`
	Session      string   `json:"session"`
	Container    string   `json:"container"`
	Host         int      `json:"host"` // host number within the session subnet
	Groups       []string `json:"groups"`
	PortSecurity bool     `json:"port_security"`
}

// Store persists the control plane. FileStore is the single-relay one; a
// replicated store (Raft, in the high-availability milestones) implements
// the same interface.
type Store interface {
	Load() (*State, error)
	Save(*State) error
}

// MemStore keeps the state in memory, for tests.
type MemStore struct{ s []byte }

func (m *MemStore) Load() (*State, error) {
	if m.s == nil {
		return nil, nil
	}
	var st State
	return &st, json.Unmarshal(m.s, &st)
}

func (m *MemStore) Save(s *State) error {
	b, err := json.Marshal(s)
	m.s = b
	return err
}

// FileStore writes the state as JSON to Path, mode 0600, through a temporary
// file and a rename, so a crash leaves either the old state or the new one.
type FileStore struct{ Path string }

// maxStateBytes bounds what Load reads.
const maxStateBytes = 64 << 20

func (f FileStore) Load() (*State, error) {
	fh, err := os.Open(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %v, want 0600 (it holds join codes)", f.Path, st.Mode().Perm())
	}
	if st.Size() > maxStateBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", f.Path, maxStateBytes)
	}
	var s State
	dec := json.NewDecoder(fh)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	return &s, nil
}

func (f FileStore) Save(s *State) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, f.Path); err != nil {
		return err
	}
	ok = true
	return nil
}
