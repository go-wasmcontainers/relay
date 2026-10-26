// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// flowLog is a class's ring of recent flow events.
type flowLog struct {
	buf  []*v1.FlowEvent
	next int
	full bool
}

func newFlowLog(n int) *flowLog { return &flowLog{buf: make([]*v1.FlowEvent, n)} }

func (l *flowLog) add(e *v1.FlowEvent) {
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
}

// last returns up to n most recent events, oldest first.
func (l *flowLog) last(n int) []*v1.FlowEvent {
	size := l.next
	if l.full {
		size = len(l.buf)
	}
	if n > size {
		n = size
	}
	out := make([]*v1.FlowEvent, 0, n)
	for i := size - n; i < size; i++ {
		idx := i
		if l.full {
			idx = (l.next + i) % len(l.buf)
		}
		out = append(out, l.buf[idx])
	}
	return out
}

// subscriber receives a class's events. Its channel is bounded: a slow
// reader loses events (counted in dropped) rather than holding memory.
type subscriber struct {
	ch       chan *v1.FlowEvent
	dropped  atomic.Uint64
	session  string // only events touching this session; empty: all
	denyOnly bool
	closed   chan struct{}
	once     sync.Once
}

func (s *subscriber) wants(e *v1.FlowEvent) bool {
	if s.denyOnly && e.Verdict != v1.Verdict_VERDICT_DENY && e.Verdict != v1.Verdict_VERDICT_REVOKED {
		return false
	}
	return s.session == "" || e.SrcSession == s.session || e.DstSession == s.session
}

func (s *subscriber) close() { s.once.Do(func() { close(s.closed) }) }

func (c *class) closeSubs() {
	for s := range c.subs {
		s.close()
	}
}

// logFlow records a decision. Relay.mu held.
func (c *class) logFlow(f firewall.Flow, srcPort, dstPort string, verdict v1.Verdict, d firewall.Decision, out, in uint64) {
	e := &v1.FlowEvent{
		TimeUnixNano: c.r.cfg.Now().UnixNano(), ClassId: c.s.ID,
		SrcPortId: srcPort, Src: f.Src.String(), DstPortId: dstPort, Dst: f.Dst.String(),
		Protocol: v1.Protocol(f.Protocol), Verdict: verdict, EgressRuleId: d.EgressRule, IngressRuleId: d.IngressRule,
		Reason: d.Reason, BytesOut: out, BytesIn: in,
	}
	if p := c.s.Ports[srcPort]; p != nil {
		e.SrcSession = p.Session
	}
	if p := c.s.Ports[dstPort]; p != nil {
		e.DstSession = p.Session
	}
	c.log.add(e)
	c.account(e, f)
	for s := range c.subs {
		if !s.wants(e) {
			continue
		}
		select {
		case s.ch <- e:
		default:
			s.dropped.Add(1)
		}
	}
}

// logDenyOnce logs a denied datagram at most once a second per flow, so a
// flood of refused datagrams does not flood the log.
func (c *class) logDenyOnce(f firewall.Flow, srcPort, dstPort string, d firewall.Decision, now time.Time) {
	k := flowKey{f.Protocol, f.Src, f.Dst}
	if t, ok := c.denySeen[k]; ok && now.Sub(t) < time.Second {
		return
	}
	if len(c.denySeen) > 4096 {
		clear(c.denySeen)
	}
	c.denySeen[k] = now
	c.logFlow(f, srcPort, dstPort, v1.Verdict_VERDICT_DENY, d, 0, 0)
}

// WatchFlows streams a class's flow events to fn until ctx ends or fn
// returns an error. backlog recent events come first. session limits the
// events to the ones touching that session (a student's own view).
func (r *Relay) WatchFlows(ctx context.Context, classID, session string, denyOnly bool, backlog int, fn func(*v1.FlowEvent) error) error {
	if backlog > 1000 {
		backlog = 1000
	}
	sub := &subscriber{ch: make(chan *v1.FlowEvent, 256), session: session, denyOnly: denyOnly, closed: make(chan struct{})}
	r.mu.Lock()
	c, ok := r.classes[classID]
	if !ok {
		r.mu.Unlock()
		return errf(KindNotFound, "no class %s", classID)
	}
	var past []*v1.FlowEvent
	for _, e := range c.log.last(backlog) {
		if sub.wants(e) {
			past = append(past, e)
		}
	}
	c.subs[sub] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(c.subs, sub)
		r.mu.Unlock()
	}()
	for _, e := range past {
		if err := fn(e); err != nil {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sub.closed:
			return nil
		case e := <-sub.ch:
			if err := fn(e); err != nil {
				return err
			}
		}
	}
}

// bucket is a token bucket. wait blocks until n tokens are there, which is
// how a session over its rate is slowed down (backpressure on its reads)
// rather than cut off.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(rate, burst float64, now func() time.Time) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, last: now(), now: now}
}

func (b *bucket) wait(ctx context.Context, n float64) error {
	if n > b.burst {
		n = b.burst
	}
	for {
		b.mu.Lock()
		t := b.now()
		b.tokens = math.Min(b.burst, b.tokens+t.Sub(b.last).Seconds()*b.rate)
		b.last = t
		if b.tokens >= n {
			b.tokens -= n
			b.mu.Unlock()
			return nil
		}
		need := time.Duration((n - b.tokens) / b.rate * float64(time.Second))
		b.mu.Unlock()
		if need < time.Millisecond {
			need = time.Millisecond
		}
		tm := time.NewTimer(need)
		select {
		case <-ctx.Done():
			tm.Stop()
			return ctx.Err()
		case <-tm.C:
		}
	}
}
