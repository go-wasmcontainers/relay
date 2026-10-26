// SPDX-License-Identifier: BSD-3-Clause

package flowmap

import (
	"strings"
	"testing"

	"github.com/go-widgets/toolkit"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

func update(seq uint64, denied bool) *v1.FlowMapUpdate {
	return &v1.FlowMapUpdate{Seq: seq,
		Clusters: []*v1.MapCluster{{Id: "s0", Label: "teacher", Teacher: true}, {Id: "s1", Label: "alice"}, {Id: "s2", Label: "bob"}},
		Nodes: []*v1.MapNode{{Id: "p1", Label: "web", Cluster: "s1", Ip: "10.42.1.2", Groups: []string{"web"}},
			{Id: "p2", Label: "curl", Cluster: "s2", Ip: "10.42.2.2"}},
		Edges: []*v1.MapEdge{{Id: "e1", SrcPort: "p2", DstPort: "p1", Protocol: v1.Protocol_PROTOCOL_TCP, Port: 80,
			Bytes: 1000, BytesPerSecond: 500, Open: 1, Opened: 1, EgressRuleId: "r-1", IngressRuleId: "r-2"},
			{Id: "e2", SrcPort: "p2", DstPort: "p1", Protocol: v1.Protocol_PROTOCOL_TCP, Port: 22, Denied: 1,
				DeniedRecently: denied, LastReason: "no ingress rule of p1 allows it"}},
		Events: []*v1.FlowEvent{{TimeUnixNano: 1e18, Verdict: v1.Verdict_VERDICT_DENY, Protocol: v1.Protocol_PROTOCOL_TCP,
			SrcPortId: "p2", Dst: "10.42.1.2:22", Reason: "no ingress rule"}},
	}
}

func TestVMApply(t *testing.T) {
	vm := NewVM()
	vm.Apply(update(1, true))
	s := vm.Snapshot()
	if s.Seq != 1 || len(s.Clusters) != 3 || s.Clusters[0] != "teacher" || len(s.Nodes) != 2 || s.Nodes[0] != "alice/web" {
		t.Fatalf("%+v", s)
	}
	if len(s.Denied) != 1 || !strings.Contains(s.Denied[0], "bob/curl -> alice/web tcp/22 (no ingress rule of p1 allows it)") {
		t.Fatalf("denied: %v", s.Denied)
	}
	if !strings.Contains(s.Status, "2 containers, 2 flows, 1 refused now") || len(s.Events) != 1 || !strings.Contains(s.Events[0], "deny tcp bob/curl") {
		t.Fatalf("%q %v", s.Status, s.Events)
	}
	// Same structure: the node list is not rebuilt (the layout is kept).
	changed := 0
	vm.Graph.Nodes.SubscribeChanged(func() { changed++ })
	u := update(2, false)
	u.Truncated, u.DroppedEvents = true, 3
	u.Edges[0].Open, u.Edges[0].BytesPerSecond = 0, 0
	vm.Apply(u)
	if changed != 0 {
		t.Fatal("an edge-only update rebuilt the nodes")
	}
	edges := vm.Graph.Edges.Slice()
	// No open stream, no rate, no recent refusal: both idle now.
	if edges[0].State != toolkit.GraphEdgeIdle || edges[1].State != toolkit.GraphEdgeIdle {
		t.Fatalf("states %v %v", edges[0].State, edges[1].State)
	}
	if !strings.Contains(vm.Status, "truncated") || !strings.Contains(vm.Status, "3 events dropped") {
		t.Fatal(vm.Status)
	}
	// A new node rebuilds.
	u = update(3, false)
	u.Nodes = append(u.Nodes, &v1.MapNode{Id: "p3", Label: "db", Cluster: "s1"})
	vm.Apply(u)
	if changed == 0 {
		t.Fatal("a new node did not rebuild the nodes")
	}
	// The event log is bounded.
	for i := range MaxEvents + 10 {
		vm.Apply(update(uint64(10+i), false))
	}
	if len(vm.Events) != MaxEvents {
		t.Fatal(len(vm.Events))
	}
}

func TestVMDetails(t *testing.T) {
	vm := NewVM()
	vm.Apply(update(1, true))
	if vm.Details() != nil {
		t.Fatal("details with no selection")
	}
	vm.Graph.Selected.Set("node:p1")
	if d := strings.Join(vm.Details(), "|"); !strings.Contains(d, "alice/web|address 10.42.1.2|groups web") {
		t.Fatal(d)
	}
	vm.Graph.Selected.Set("edge:e1")
	d := strings.Join(vm.Details(), "|")
	if !strings.Contains(d, "bob/curl -> alice/web tcp/80") || !strings.Contains(d, "allowed by r-1 (egress), r-2 (ingress)") {
		t.Fatal(d)
	}
	vm.Graph.Selected.Set("edge:e2")
	if d := strings.Join(vm.Details(), "|"); !strings.Contains(d, "last refusal: no ingress rule") {
		t.Fatal(d)
	}
	for _, s := range []string{"node:gone", "edge:gone", "bogus"} {
		vm.Graph.Selected.Set(s)
		if vm.Details() != nil {
			t.Fatal(s)
		}
	}
	if vm.name("unknown") != "unknown" {
		t.Fatal("name of an unknown port")
	}
	vm.nodes["orphan"] = &v1.MapNode{Label: "o", Cluster: "nowhere"}
	if vm.name("orphan") != "o" {
		t.Fatal("name without a cluster")
	}
	if category(&v1.MapNode{}) != "no group" {
		t.Fatal("category")
	}
}

func TestScene(t *testing.T) {
	s := NewScene(100, 100) // clamped to the minimum
	if w, h := s.Size(); w != 640 || h != 360 {
		t.Fatal(w, h)
	}
	changes := 0
	s.OnChange = func() { changes++ }
	if s.AnimationStep(0.016) {
		t.Fatal("repaint with nothing posted")
	}
	s.Post(update(1, true))
	s.Post(update(2, true)) // coalesced: only seq 2 drawn, both updates' events kept
	if !s.AnimationStep(0.016) || s.VM.Seq != 2 || len(s.VM.Events) != 2 || changes != 1 {
		t.Fatalf("seq %d events %d changes %d", s.VM.Seq, len(s.VM.Events), changes)
	}
	buf := make([]byte, 4*640*360)
	s.Draw(buf)
	box, ok := s.Graph().NodeBox("p1")
	if !ok {
		t.Fatal("no box")
	}
	if !s.Click(box.X+1, box.Y+1) || s.VM.Graph.Selected.Get() != "node:p1" {
		t.Fatal("click")
	}
	s.Draw(buf) // with details
	if s.Click(639, 10) {
		t.Fatal("a click in the panel went to the graph")
	}
	if !s.KeyDown("Escape") || s.VM.Graph.Selected.Get() != "" {
		t.Fatal("escape")
	}
	s.SetFilter("alice")
	if s.VM.Snapshot().Filter != "alice" {
		t.Fatal("filter")
	}
	if s.Move(1, 1) || s.Release(1, 1) || s.Context(1, 1) || s.Char("a") {
		t.Fatal("unused events")
	}
	s.OnChange = nil
	s.SetFilter("")
}

// BenchmarkSceneFrame: one update applied and one 1920x1080 frame drawn,
// with 40 students of 5 containers and 1000 edges.
func BenchmarkSceneFrame(b *testing.B) {
	u := &v1.FlowMapUpdate{}
	for c := range 40 {
		id := "s" + itoa(c)
		u.Clusters = append(u.Clusters, &v1.MapCluster{Id: id, Label: "student-" + itoa(c)})
		for k := range 5 {
			u.Nodes = append(u.Nodes, &v1.MapNode{Id: "p" + itoa(c*5+k), Label: "c" + itoa(k), Cluster: id, Groups: []string{"g" + itoa(k%3)}})
		}
	}
	for i := range 1000 {
		u.Edges = append(u.Edges, &v1.MapEdge{Id: "e" + itoa(i), SrcPort: "p" + itoa(i%200), DstPort: "p" + itoa((i*7+3)%200),
			Port: 80, BytesPerSecond: float64(i * 100), Open: 1, DeniedRecently: i%10 == 0})
	}
	s := NewScene(1920, 1080)
	s.Theme = toolkit.DefaultDark()
	buf := make([]byte, 4*1920*1080)
	s.Post(u)
	s.AnimationStep(0)
	s.Draw(buf)
	b.ResetTimer()
	for i := range b.N {
		u.Seq = uint64(i)
		s.Post(u)
		s.AnimationStep(0)
		s.Draw(buf)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
