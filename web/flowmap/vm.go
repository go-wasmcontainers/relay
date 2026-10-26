// SPDX-License-Identifier: BSD-3-Clause

// Package flowmap is the relay's live flow-map page: a view model fed by
// FlowLogService.WatchFlowMap updates, drawn with go-widgets' GraphView. The
// view model and the scene are plain Go, tested natively; package main in
// ./wasm wires them to the browser.
package flowmap

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-widgets/toolkit"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// MaxEvents bounds the event log the page keeps.
const MaxEvents = 200

// Event is one line of the page's event log.
type Event struct {
	Time    string
	Denied  bool
	Message string
}

// VM is the page's view model. Graph is what the GraphView draws; the other
// fields feed the details panel. Apply is called on the UI goroutine.
type VM struct {
	Graph  *toolkit.GraphViewModel
	Events []Event
	// Status is the line under the title: connection and counts.
	Status string
	Seq    uint64

	nodes   map[string]*v1.MapNode
	edges   map[string]*v1.MapEdge
	cluster map[string]*v1.MapCluster
	shape   string // the structure the graph lists hold, to skip no-op rebuilds
}

// NewVM returns an empty view model.
func NewVM() *VM {
	return &VM{Graph: toolkit.NewGraphViewModel(), nodes: map[string]*v1.MapNode{}, edges: map[string]*v1.MapEdge{},
		cluster: map[string]*v1.MapCluster{}, Status: "connecting…"}
}

// Apply takes one update. Clusters and nodes are rebuilt only when their set
// changed (so the GraphView keeps its layout); edges are replaced every time.
func (vm *VM) Apply(u *v1.FlowMapUpdate) {
	vm.Seq = u.Seq
	clear(vm.nodes)
	clear(vm.cluster)
	clear(vm.edges)
	var shape strings.Builder
	for _, c := range u.Clusters {
		vm.cluster[c.Id] = c
		fmt.Fprintf(&shape, "c%s|%s;", c.Id, c.Label)
	}
	for _, n := range u.Nodes {
		vm.nodes[n.Id] = n
		fmt.Fprintf(&shape, "n%s|%s|%s|%s;", n.Id, n.Label, n.Cluster, category(n))
	}
	if s := shape.String(); s != vm.shape {
		vm.shape = s
		var cs []toolkit.GraphCluster
		for _, c := range u.Clusters {
			label := c.Label
			if c.Teacher {
				label = "teacher"
			}
			cs = append(cs, toolkit.GraphCluster{ID: c.Id, Label: label})
		}
		var ns []toolkit.GraphNode
		for _, n := range u.Nodes {
			ns = append(ns, toolkit.GraphNode{ID: n.Id, Label: n.Label, Cluster: n.Cluster, Category: category(n)})
		}
		vm.Graph.Clusters.Clear()
		vm.Graph.Clusters.Append(cs...)
		vm.Graph.Nodes.Clear()
		vm.Graph.Nodes.Append(ns...)
	}
	var es []toolkit.GraphEdge
	denied := 0
	for _, e := range u.Edges {
		vm.edges[e.Id] = e
		st := toolkit.GraphEdgeNormal
		switch {
		case e.DeniedRecently:
			st = toolkit.GraphEdgeDenied
			denied++
		case e.Open == 0 && e.BytesPerSecond == 0:
			st = toolkit.GraphEdgeIdle
		}
		es = append(es, toolkit.GraphEdge{ID: e.Id, From: e.SrcPort, To: e.DstPort, Label: edgeLabel(e),
			Weight: e.BytesPerSecond, State: st})
	}
	vm.Graph.Edges.Clear()
	vm.Graph.Edges.Append(es...)
	for _, ev := range u.Events {
		vm.Events = append(vm.Events, vm.event(ev))
	}
	if n := len(vm.Events); n > MaxEvents {
		vm.Events = slices.Clone(vm.Events[n-MaxEvents:])
	}
	vm.Status = fmt.Sprintf("%d containers, %d flows, %d refused now", len(u.Nodes), len(u.Edges), denied)
	if u.Truncated {
		vm.Status += " (map truncated)"
	}
	if u.DroppedEvents > 0 {
		vm.Status += fmt.Sprintf(" (%d events dropped)", u.DroppedEvents)
	}
}

// category colours a node by its first security group.
func category(n *v1.MapNode) string {
	if len(n.Groups) == 0 {
		return "no group"
	}
	return n.Groups[0]
}

func protoName(p v1.Protocol) string {
	return strings.ToLower(strings.TrimPrefix(p.String(), "PROTOCOL_"))
}

func edgeLabel(e *v1.MapEdge) string {
	return fmt.Sprintf("%s/%d", protoName(e.Protocol), e.Port)
}

func (vm *VM) name(portID string) string {
	n := vm.nodes[portID]
	if n == nil {
		return portID
	}
	if c := vm.cluster[n.Cluster]; c != nil {
		return c.Label + "/" + n.Label
	}
	return n.Label
}

func (vm *VM) event(e *v1.FlowEvent) Event {
	verdict := strings.ToLower(strings.TrimPrefix(e.Verdict.String(), "VERDICT_"))
	msg := fmt.Sprintf("%s %s %s -> %s", verdict, protoName(e.Protocol), vm.name(e.SrcPortId), e.Dst)
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	t := ""
	if e.TimeUnixNano != 0 {
		t = time.Unix(0, e.TimeUnixNano).Format("15:04:05")
	}
	return Event{Time: t, Denied: e.Verdict == v1.Verdict_VERDICT_DENY || e.Verdict == v1.Verdict_VERDICT_REVOKED, Message: msg}
}

// Details describes the selection for the details panel.
func (vm *VM) Details() []string {
	sel := vm.Graph.Selected.Get()
	kind, id, _ := strings.Cut(sel, ":")
	switch kind {
	case "node":
		n := vm.nodes[id]
		if n == nil {
			return nil
		}
		return []string{vm.name(id), "address " + n.Ip, "groups " + strings.Join(n.Groups, ", ")}
	case "edge":
		e := vm.edges[id]
		if e == nil {
			return nil
		}
		out := []string{vm.name(e.SrcPort) + " -> " + vm.name(e.DstPort) + " " + edgeLabel(e),
			fmt.Sprintf("open %d, opened %d, refused %d", e.Open, e.Opened, e.Denied),
			fmt.Sprintf("%d bytes, %.0f B/s", e.Bytes, e.BytesPerSecond)}
		if e.EgressRuleId != "" || e.IngressRuleId != "" {
			out = append(out, "allowed by "+e.EgressRuleId+" (egress), "+e.IngressRuleId+" (ingress)")
		}
		if e.LastReason != "" {
			out = append(out, "last refusal: "+e.LastReason)
		}
		return out
	}
	return nil
}

// State is what the page exposes to its tests: the view model, not pixels.
type State struct {
	Seq      uint64   `json:"seq"`
	Status   string   `json:"status"`
	Clusters []string `json:"clusters"`
	Nodes    []string `json:"nodes"`
	Edges    []string `json:"edges"`
	Denied   []string `json:"denied"`
	Selected string   `json:"selected"`
	Filter   string   `json:"filter"`
	Events   []string `json:"events"`
}

// Snapshot is the view model as plain data.
func (vm *VM) Snapshot() State {
	s := State{Seq: vm.Seq, Status: vm.Status, Selected: vm.Graph.Selected.Get(), Filter: vm.Graph.Filter.Get()}
	for _, c := range vm.Graph.Clusters.Slice() {
		s.Clusters = append(s.Clusters, c.Label)
	}
	for _, n := range vm.Graph.Nodes.Slice() {
		s.Nodes = append(s.Nodes, vm.name(n.ID))
	}
	for _, e := range vm.Graph.Edges.Slice() {
		d := vm.edges[e.ID]
		line := vm.name(d.SrcPort) + " -> " + vm.name(d.DstPort) + " " + e.Label
		s.Edges = append(s.Edges, line)
		if e.State == toolkit.GraphEdgeDenied {
			s.Denied = append(s.Denied, line+" ("+d.LastReason+")")
		}
	}
	for _, e := range vm.Events {
		s.Events = append(s.Events, e.Message)
	}
	return s
}
