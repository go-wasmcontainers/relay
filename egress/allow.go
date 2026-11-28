// SPDX-License-Identifier: BSD-3-Clause

package egress

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Port is the only port egress reaches in v1 (decision D3).
const Port = 443

// MaxAllowlist bounds the entries of an allowlist.
const MaxAllowlist = 256

// Dest is one allowlisted destination: an exact host name and a port.
type Dest struct {
	Host string
	Port uint16
}

func (d Dest) String() string { return d.Host + ":" + strconv.Itoa(int(d.Port)) }

// Allowlist is a non-empty set of exact host:port destinations.
type Allowlist struct {
	set  map[Dest]struct{}
	list []Dest
}

// ParseAllowlist parses "host:443" entries. It refuses an empty list, a
// wildcard, a CIDR, an IP literal, a bare TLD, a missing or non-443 port, a
// name that is not a lower-case ASCII hostname, and more than MaxAllowlist
// entries. There is no way to waive any of it (decision D5, threat model
// section 5).
func ParseAllowlist(entries []string) (*Allowlist, error) {
	if len(entries) == 0 {
		return nil, errors.New("egress: the allowlist is empty; egress needs at least one host:443")
	}
	if len(entries) > MaxAllowlist {
		return nil, fmt.Errorf("egress: %d allowlist entries, at most %d", len(entries), MaxAllowlist)
	}
	a := &Allowlist{set: map[Dest]struct{}{}}
	for _, e := range entries {
		d, err := ParseDest(e)
		if err != nil {
			return nil, err
		}
		if _, dup := a.set[d]; dup {
			continue
		}
		a.set[d] = struct{}{}
		a.list = append(a.list, d)
	}
	sort.Slice(a.list, func(i, j int) bool { return a.list[i].String() < a.list[j].String() })
	return a, nil
}

// ParseDest parses one "host:443" entry.
func ParseDest(e string) (Dest, error) {
	i := strings.LastIndexByte(e, ':')
	if i < 0 {
		return Dest{}, fmt.Errorf("egress: %q has no port; write host:%d", e, Port)
	}
	host, ps := e[:i], e[i+1:]
	port, err := strconv.ParseUint(ps, 10, 16)
	if err != nil || strconv.FormatUint(port, 10) != ps {
		return Dest{}, fmt.Errorf("egress: %q: bad port", e)
	}
	if port != Port {
		return Dest{}, fmt.Errorf("egress: %q: only port %d is allowed", e, Port)
	}
	if err := checkHost(host); err != nil {
		return Dest{}, fmt.Errorf("egress: %q: %w", e, err)
	}
	return Dest{Host: host, Port: Port}, nil
}

func checkHost(h string) error {
	switch {
	case h == "":
		return errors.New("empty host")
	case len(h) > 253:
		return errors.New("host longer than 253 bytes")
	case strings.ContainsAny(h, "*?/\\@[] "):
		return errors.New("wildcards, CIDR, paths and brackets are refused; write an exact host name")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return errors.New("a bare name or TLD is refused; write a fully qualified host name")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("not a host name")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("host names are lower-case ASCII letters, digits and '-' (write punycode for an IDN)")
			}
		}
	}
	// An IP literal ends in a number and no TLD starts with a digit; IPv6
	// literals fail the label alphabet above (':').
	last := labels[len(labels)-1]
	if last[0] >= '0' && last[0] <= '9' {
		return errors.New("an IP address is refused (the last label must not start with a digit); write a host name")
	}
	return nil
}

// Has reports whether name:port is allowlisted. name is matched
// case-insensitively with one trailing dot ignored.
func (a *Allowlist) Has(name string, port uint16) bool {
	if a == nil {
		return false
	}
	_, ok := a.set[Dest{Host: Normalize(name), Port: port}]
	return ok
}

// Hosts returns the entries, sorted, for display.
func (a *Allowlist) Hosts() []Dest { return append([]Dest(nil), a.list...) }

// Normalize lower-cases an ASCII name and drops one trailing dot.
func Normalize(name string) string {
	name = strings.TrimSuffix(name, ".")
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
