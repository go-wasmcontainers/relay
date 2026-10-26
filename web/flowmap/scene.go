// SPDX-License-Identifier: BSD-3-Clause

package flowmap

import (
	"sync"

	"github.com/go-widgets/painter"
	"github.com/go-widgets/toolkit"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// PanelW is the width of the details panel on the right.
const PanelW = 360

// Scene is the page: the graph on the left, the selection's details and the
// event log on the right. It implements webcanvas.App, Animator and Resizer.
type Scene struct {
	VM    *VM
	Theme *toolkit.Theme
	// OnChange is called after the view model changed (the page publishes
	// its state for tests and updates the status line).
	OnChange func()

	graph  *toolkit.GraphView
	log    *toolkit.LogView
	logged int
	w, h   int

	mu      sync.Mutex
	pending []*v1.FlowMapUpdate
}

// NewScene builds the page at w x h.
func NewScene(w, h int) *Scene {
	s := &Scene{VM: NewVM(), Theme: toolkit.DefaultLight(), log: toolkit.NewLogView()}
	s.graph = toolkit.NewGraphView(s.VM.Graph)
	s.graph.ShowLegend = true
	s.graph.SetFocused(true)
	s.Resize(w, h)
	return s
}

// Post queues an update from any goroutine; AnimationStep applies it on the
// UI goroutine.
func (s *Scene) Post(u *v1.FlowMapUpdate) {
	s.mu.Lock()
	s.pending = append(s.pending, u)
	s.mu.Unlock()
}

// AnimationStep applies what arrived since the last frame. Only the newest
// map is drawn, but every update's events are kept.
func (s *Scene) AnimationStep(float64) bool {
	s.mu.Lock()
	ps := s.pending
	s.pending = nil
	s.mu.Unlock()
	if len(ps) == 0 {
		return false
	}
	for _, u := range ps[:len(ps)-1] {
		s.VM.Events = append(s.VM.Events, eventsOf(s.VM, u)...)
	}
	s.VM.Apply(ps[len(ps)-1])
	for _, e := range s.VM.Events[min(s.logged, len(s.VM.Events)):] {
		level := toolkit.LogInfo
		if e.Denied {
			level = toolkit.LogError
		}
		s.log.Append(e.Time, level, e.Message)
	}
	s.logged = len(s.VM.Events)
	s.changed()
	return true
}

func eventsOf(vm *VM, u *v1.FlowMapUpdate) []Event {
	var out []Event
	for _, e := range u.Events {
		out = append(out, vm.event(e))
	}
	return out
}

func (s *Scene) changed() {
	if s.OnChange != nil {
		s.OnChange()
	}
}

// SetFilter sets the graph's filter (from the page's search box).
func (s *Scene) SetFilter(f string) {
	s.VM.Graph.Filter.Set(f)
	s.changed()
}

// Size is the current surface size.
func (s *Scene) Size() (int, int) { return s.w, s.h }

// Resize lays the scene out at w x h (at least 640 x 360).
func (s *Scene) Resize(w, h int) (int, int) {
	s.w, s.h = max(w, 640), max(h, 360)
	s.graph.SetBounds(toolkit.Rect{X: 0, Y: 0, W: s.w - PanelW, H: s.h})
	s.log.SetBounds(toolkit.Rect{X: s.w - PanelW, Y: s.h / 3, W: PanelW, H: s.h - s.h/3})
	return s.w, s.h
}

// Draw paints the whole scene.
func (s *Scene) Draw(buf []byte) {
	p := painter.NewPixelPainter(buf, s.w, s.h)
	th := s.Theme
	s.graph.Draw(p, th)
	x := s.w - PanelW
	p.FillRect(painter.Rect{X: x, Y: 0, W: PanelW, H: s.h / 3}, th.Surface)
	p.FillRect(painter.Rect{X: x, Y: 0, W: 1, H: s.h}, th.Border)
	y := 8
	lines := s.VM.Details()
	if len(lines) == 0 {
		lines = []string{"Click a container or a flow;", "arrows move between containers."}
	}
	for _, l := range lines {
		toolkit.DrawText(p, x+10, y, l, th.OnSurface)
		y += toolkit.GlyphHeight() + 6
	}
	s.log.Draw(p, th)
}

// Click selects in the graph.
func (s *Scene) Click(x, y int) bool {
	if x >= s.w-PanelW {
		return false
	}
	s.graph.OnEvent(toolkit.Event{Kind: toolkit.EventClick, X: x, Y: y})
	s.changed()
	return true
}

// KeyDown moves the selection.
func (s *Scene) KeyDown(k string) bool {
	s.graph.OnEvent(toolkit.Event{Kind: toolkit.EventKeyDown, Code: k})
	s.changed()
	return true
}

// Move, Release, Context and Char do nothing on this page (the filter is an
// HTML input outside the canvas, so dead keys and IMEs work in it).
func (s *Scene) Move(int, int) bool    { return false }
func (s *Scene) Release(int, int) bool { return false }
func (s *Scene) Context(int, int) bool { return false }
func (s *Scene) Char(string) bool      { return false }

// Graph is the scene's graph widget (tests).
func (s *Scene) Graph() *toolkit.GraphView { return s.graph }
