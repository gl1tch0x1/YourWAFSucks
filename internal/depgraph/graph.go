package depgraph

import "sync"

// Node is a single mutation in the dependency graph. Parent is the optional
// direct parent recorded at insertion time; edges added with AddEdge take
// precedence for traversal.
type Node struct {
	ID        string
	Parent    string
	Technique string
	Meta      map[string]string
}

// Graph is a directed dependency graph of mutations. It is safe for concurrent use.
type Graph struct {
	mu      sync.RWMutex
	nodes   map[string]Node
	order   []string
	edges   map[string][]string
	parents map[string][]string
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes:   make(map[string]Node),
		edges:   make(map[string][]string),
		parents: make(map[string][]string),
	}
}

// AddNode inserts or replaces a node, preserving first-insertion order.
func (g *Graph) AddNode(n Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.nodes[n.ID]; !ok {
		g.order = append(g.order, n.ID)
	}
	g.nodes[n.ID] = n
}

// AddEdge records a directed edge from parent to child. Missing nodes are
// created as placeholders so edges never dangle.
func (g *Graph) AddEdge(parent, child string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.ensureLocked(parent)
	g.ensureLocked(child)

	if !contains(g.edges[parent], child) {
		g.edges[parent] = append(g.edges[parent], child)
	}
	if !contains(g.parents[child], parent) {
		g.parents[child] = append(g.parents[child], parent)
	}
}

func (g *Graph) ensureLocked(id string) {
	if _, ok := g.nodes[id]; ok {
		return
	}
	g.nodes[id] = Node{ID: id}
	g.order = append(g.order, id)
}

// TopoSort returns all node IDs in dependency order: parents before children,
// with independent nodes kept in insertion order. Cycles are tolerated and the
// remaining nodes are appended in insertion order rather than hanging.
func (g *Graph) TopoSort() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.topoLocked()
}

func (g *Graph) topoLocked() []string {
	indeg := make(map[string]int, len(g.nodes))
	for id := range g.nodes {
		for _, p := range g.parents[id] {
			if _, ok := g.nodes[p]; ok {
				indeg[id]++
			}
		}
	}

	emitted := make(map[string]bool, len(g.nodes))
	out := make([]string, 0, len(g.nodes))

	for len(out) < len(g.nodes) {
		progress := false
		for _, id := range g.order {
			if emitted[id] || indeg[id] != 0 {
				continue
			}
			emitted[id] = true
			out = append(out, id)
			progress = true
			for _, c := range g.edges[id] {
				if _, ok := g.nodes[c]; ok {
					indeg[c]--
				}
			}
		}
		if !progress {
			// Cycle: emit the remainder in insertion order.
			for _, id := range g.order {
				if !emitted[id] {
					emitted[id] = true
					out = append(out, id)
				}
			}
		}
	}
	return out
}

// Children returns the direct children of id in insertion order.
func (g *Graph) Children(id string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	src := g.edges[id]
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// Roots returns nodes without parents, in insertion order.
func (g *Graph) Roots() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0)
	for _, id := range g.order {
		if len(g.parents[id]) == 0 {
			out = append(out, id)
		}
	}
	return out
}

// Prioritize orders every node so that the successful nodes and all of their
// transitive descendants come first (in topological order), followed by the
// rest. Unknown IDs are ignored.
func (g *Graph) Prioritize(successful []string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	topo := g.topoLocked()

	priority := make(map[string]bool, len(successful))
	queue := make([]string, 0, len(successful))
	for _, id := range successful {
		if _, ok := g.nodes[id]; !ok || priority[id] {
			continue
		}
		priority[id] = true
		queue = append(queue, id)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range g.edges[cur] {
			if priority[c] {
				continue
			}
			if _, ok := g.nodes[c]; !ok {
				continue
			}
			priority[c] = true
			queue = append(queue, c)
		}
	}

	out := make([]string, 0, len(topo))
	for _, id := range topo {
		if priority[id] {
			out = append(out, id)
		}
	}
	for _, id := range topo {
		if !priority[id] {
			out = append(out, id)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
