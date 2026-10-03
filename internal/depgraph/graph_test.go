package depgraph

import (
	"reflect"
	"testing"
)

func indexOf(list []string, id string) int {
	for i, v := range list {
		if v == id {
			return i
		}
	}
	return -1
}

func TestTopoSortDiamond(t *testing.T) {
	g := New()
	for _, id := range []string{"A", "B", "C", "D"} {
		g.AddNode(Node{ID: id})
	}
	g.AddEdge("A", "B")
	g.AddEdge("A", "C")
	g.AddEdge("B", "D")
	g.AddEdge("C", "D")

	got := g.TopoSort()
	want := []string{"A", "B", "C", "D"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TopoSort() = %v, want %v", got, want)
	}

	if got := g.Children("A"); !reflect.DeepEqual(got, []string{"B", "C"}) {
		t.Fatalf("Children(A) = %v, want [B C]", got)
	}
	if got := g.Roots(); !reflect.DeepEqual(got, []string{"A"}) {
		t.Fatalf("Roots() = %v, want [A]", got)
	}
}

func TestTopoSortIndependentStableByInsertion(t *testing.T) {
	g := New()
	for _, id := range []string{"x", "y", "z"} {
		g.AddNode(Node{ID: id})
	}
	got := g.TopoSort()
	want := []string{"x", "y", "z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TopoSort() = %v, want %v", got, want)
	}
}

func TestTopoSortHandlesCycle(t *testing.T) {
	g := New()
	for _, id := range []string{"A", "B", "C"} {
		g.AddNode(Node{ID: id})
	}
	g.AddEdge("A", "B")
	g.AddEdge("B", "C")
	g.AddEdge("C", "A")

	got := g.TopoSort()
	if len(got) != 3 {
		t.Fatalf("TopoSort() returned %d nodes, want 3", len(got))
	}
	seen := make(map[string]bool)
	for _, id := range got {
		if seen[id] {
			t.Fatalf("TopoSort() duplicated node %q in %v", id, got)
		}
		seen[id] = true
	}
}

func TestPrioritizePromotesDescendants(t *testing.T) {
	g := New()
	for _, id := range []string{"A", "B", "C", "D", "E"} {
		g.AddNode(Node{ID: id})
	}
	g.AddEdge("A", "B")
	g.AddEdge("B", "C")
	g.AddEdge("D", "E")

	got := g.Prioritize([]string{"B"})
	// B and its descendant C come first in topo order, then the rest (A, D, E).
	want := []string{"B", "C", "A", "D", "E"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Prioritize(B) = %v, want %v", got, want)
	}

	if i, j := indexOf(got, "B"), indexOf(got, "C"); i > j {
		t.Fatalf("descendant C should follow successful B: %v", got)
	}
}

func TestPrioritizeIgnoresUnknown(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "A"})
	g.AddNode(Node{ID: "B"})
	g.AddEdge("A", "B")

	got := g.Prioritize([]string{"missing"})
	want := []string{"A", "B"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Prioritize(unknown) = %v, want %v", got, want)
	}
}
