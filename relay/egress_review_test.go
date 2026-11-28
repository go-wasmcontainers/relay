// SPDX-License-Identifier: BSD-3-Clause

package relay_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/egress"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/relay"
)

// Review findings of PR 19, each held by a test that failed first.

// The class firewall judges an outside destination: with every rule of every
// group deleted the guest cannot dial out, and the gateway never dials.
func TestEgressHonoursTheClassFirewall(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	gs, err := x.r.ListSecurityGroups(x.class.Id)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range gs {
		for _, r := range g.Rules {
			if err := x.r.DeleteRule(x.class.Id, r.Id); err != nil {
				t.Fatal(err)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("the test did not empty the policy")
	}
	resolve(t, ep, "api.example.org")
	_, err = dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.ECONNREFUSED)
	if x.dialed.Load() != 0 {
		t.Fatal("the gateway dialled through an empty firewall")
	}
	if got := x.state().Counters; got.Allowed != 0 {
		t.Fatalf("counted as allowed: %v", got)
	}
	var denied int
	wctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = x.r.WatchFlows(wctx, x.class.Id, "", true, 1000, func(ev *v1.FlowEvent) error {
		if ev.Verdict == v1.Verdict_VERDICT_DENY && strings.Contains(ev.Reason, "egress") {
			denied++
		}
		return nil
	})
	if denied == 0 {
		t.Fatal("no flow event for the firewall refusal")
	}
}

// A name one member asked for is not shown to the others, and the refusal is
// a flow event (cleaned).
func TestEgressRefusedLookupIsAFlowEventNotABroadcast(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ann := x.person("ann")
	evil := "ann-private.example\n\x1b[2J<img src=x onerror=alert(1)>"
	_, _ = ann.Resolve(ctx(t), evil)
	_, _ = ann.Resolve(ctx(t), "not-listed.example.org")
	eventually(t, "the denials are counted", func() bool { return x.state().Counters.DeniedNotAllowlisted >= 2 })
	bob, _ := x.person("bob")
	for _, st := range []*v1.EgressState{bob.Welcome().Egress, x.state()} {
		if h := st.Counters.LastDeniedHost; h != "" {
			t.Fatalf("a guest-chosen name is broadcast: %q", h)
		}
		if st.Counters.LastDeniedReason == "" || st.Counters.LastDeniedUnix == 0 {
			t.Fatalf("the denial itself is not shown: %v", st.Counters)
		}
	}
	wctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	events := 0
	_ = x.r.WatchFlows(wctx, x.class.Id, "", true, 1000, func(ev *v1.FlowEvent) error {
		if strings.ContainsAny(ev.Reason, "\n\x1b<>") {
			t.Errorf("an uncleaned name in a flow event: %q", ev.Reason)
		}
		if strings.Contains(ev.Reason, "lookup") {
			events++
		}
		return nil
	})
	if events != 2 {
		t.Fatalf("%d lookup flow events, want 2", events)
	}
}

// CDNs share addresses: two allowlisted names on one address both work.
func TestEgressSharedAddressServesBothNames(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	x.dns.set("other.example.org", apiIP)
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	resolve(t, ep, "other.example.org")
	for _, name := range []string{"api.example.org", "other.example.org"} {
		c, err := dialTLS(t, ep, apiIP, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		echo(t, c, "hello "+name)
		c.Close()
	}
	if _, err := dialTLS(t, ep, apiIP, "evil.example.org"); err == nil {
		t.Fatal("an unpinned name was accepted on the shared address")
	}
	eventually(t, "released", func() bool { return x.state().Counters.ActiveStreams == 0 })
}

// The lookup name is rooted: resolv.conf search domains must not apply.
func TestEgressLookupNameIsRooted(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	x.dns.mu.Lock()
	last := x.dns.last
	x.dns.mu.Unlock()
	if last != "api.example.org." {
		t.Fatalf("the outside lookup was for %q", last)
	}
}

// An outside answer says how long it holds (the pin's lifetime); an unknown
// name carries none.
func TestEgressResolvedCarriesTheTTL(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	got, ttl, err := ep.ResolveTTL(ctx(t), "api.example.org")
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if ttl != egress.PinTTL {
		t.Fatalf("ttl %v, want %v", ttl, egress.PinTTL)
	}
}

// clientHello captures the first TLS record a real client sends for name.
func clientHello(t testing.TB, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer b.Close()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
		a.Close()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(b, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// D3: the outside never reaches the guest before the ClientHello is checked.
func TestEgressOutsideSilentBeforeTheHello(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	x.greet.Store(true)
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialRaw(t, ep, apiIP, 443)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := c.Read(buf); n != 0 || !isTimeout(err) {
		t.Fatalf("the outside's bytes reached the guest before its hello: %q %v", buf[:n], err)
	}
}

// RFC 8446 4.1.4: a HelloRetryRequest makes the client send a second
// ClientHello the gateway never saw: refused.
func TestEgressHelloRetryRequestIsRefused(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	x.hrr.Store(true)
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	if _, err := dialTLS(t, ep, apiIP, "api.example.org"); err == nil {
		t.Fatal("a handshake that went through a HelloRetryRequest")
	}
	eventually(t, "counted as a TLS refusal", func() bool { return x.state().Counters.DeniedTlsName == 1 })
}

// A hello trickled one byte at a time keeps the stream "active" for the idle
// timer: only the hello deadline ends it (slowloris).
func TestEgressTrickledHelloTimesOut(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{Idle: 2 * time.Second, HelloTimeout: 300 * time.Millisecond})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialRaw(t, ep, apiIP, 443)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello := clientHello(t, "api.example.org")
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for _, b := range hello {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := c.Write([]byte{b}); err != nil {
				return
			}
		}
	}()
	c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the trickled hello was not cut off by the hello deadline: %v", err)
	}
}

// A refresh judges the identity against the audience again: a member whose
// group was dropped loses egress at once and cannot renew the token.
func TestEgressRefreshCutsAMemberTheAudienceNoLongerNames(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	id := &relay.Identity{Issuer: "https://idp", Subject: "ann", Groups: []string{"students"}}
	j, err := x.r.Join(x.class.JoinCode, "ann", id)
	if err != nil {
		t.Fatal(err)
	}
	ep := attach(t, x.connect(j.Token), "web")
	resolve(t, ep, "api.example.org")
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo(t, c, "before")
	if _, err := x.r.Refresh(j.Token, id); err != nil {
		t.Fatalf("a member still named is refused: %v", err)
	}
	left := &relay.Identity{Issuer: "https://idp", Subject: "ann", Groups: []string{"alumni"}}
	if _, err := x.r.Refresh(j.Token, left); relay.ErrKind(err) != relay.KindDenied {
		t.Fatalf("refresh after leaving the group: %v", err)
	}
	if _, err := x.r.Refresh(j.Token, nil); err == nil {
		t.Fatal("refresh without an identity")
	}
	eventually(t, "the stream is cut", func() bool { return x.state().Counters.ActiveStreams == 0 })
	_, err = dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.ECONNREFUSED)
}

// A lookup in flight when the join code rotates cannot pin afterwards.
func TestEgressLookupInFlightDuringRotation(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	x.dns.mu.Lock()
	x.dns.hold = func(string) {
		once.Do(func() { close(entered) })
		<-release
	}
	x.dns.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resolve(t, ep, "api.example.org")
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the lookup never reached the resolver")
	}
	if _, err := x.r.RotateJoinCode(x.class.Id); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	x.dns.mu.Lock()
	x.dns.hold = nil
	x.dns.mu.Unlock()
	if _, err := dialRaw(t, ep, apiIP, 443); err == nil {
		t.Fatal("a lookup begun before the rotation pinned an address after it")
	} else {
		wantErrno(t, err, syscall.ECONNREFUSED)
	}
	if x.dialed.Load() != 0 {
		t.Fatal("dialled")
	}
}

// A denied refresh cuts outside access on the live connection and keeps it
// cut: the same token resolves and connects no more until a refresh succeeds.
func TestEgressDeniedRefreshKeepsEgressCut(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	id := &relay.Identity{Issuer: "https://idp", Subject: "ann", Groups: []string{"students"}}
	j, err := x.r.Join(x.class.JoinCode, "ann", id)
	if err != nil {
		t.Fatal(err)
	}
	ep := attach(t, x.connect(j.Token), "web")
	resolve(t, ep, "api.example.org")
	left := &relay.Identity{Issuer: "https://idp", Subject: "ann", Groups: []string{"alumni"}}
	if _, err := x.r.Refresh(j.Token, left); relay.ErrKind(err) != relay.KindDenied {
		t.Fatalf("refresh after leaving the group: %v", err)
	}
	eventually(t, "the streams are cut", func() bool { return x.state().Counters.ActiveStreams == 0 })
	if got := resolve(t, ep, "api.example.org"); len(got) != 0 {
		t.Fatalf("a cut session resolved an outside name: %v", got)
	}
	if c, err := dialRaw(t, ep, apiIP, 443); err == nil {
		c.Close()
		t.Fatal("a cut session connected outside")
	} else {
		wantErrno(t, err, syscall.ECONNREFUSED)
	}
	if x.dialed.Load() != 0 {
		t.Fatal("the gateway dialled for a cut session")
	}
	// The connect was refused for the cut, not for a missing pin.
	if got := x.state().Counters.LastDeniedReason; got != "the session's refresh was denied" {
		t.Fatalf("last denial: %q", got)
	}
	// A successful refresh gives it back.
	if _, err := x.r.Refresh(j.Token, id); err != nil {
		t.Fatal(err)
	}
	if got := resolve(t, ep, "api.example.org"); len(got) == 0 {
		t.Fatal("a refreshed session cannot resolve")
	}
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "after the refresh")
	c.Close()
}

// A refresh with another identity fails and cuts the session as well.
func TestEgressFailedRefreshWithOtherIdentityCuts(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	id := &relay.Identity{Issuer: "https://idp", Subject: "ann", Groups: []string{"students"}}
	j, err := x.r.Join(x.class.JoinCode, "ann", id)
	if err != nil {
		t.Fatal(err)
	}
	ep := attach(t, x.connect(j.Token), "web")
	resolve(t, ep, "api.example.org")
	other := &relay.Identity{Issuer: "https://idp", Subject: "bob", Groups: []string{"students"}}
	if _, err := x.r.Refresh(j.Token, other); err == nil {
		t.Fatal("refresh with another identity")
	}
	if got := resolve(t, ep, "api.example.org"); len(got) != 0 {
		t.Fatalf("a cut session resolved: %v", got)
	}
}
