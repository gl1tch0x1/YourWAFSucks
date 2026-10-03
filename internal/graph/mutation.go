package graph

import (
	"fmt"
	"sync"
)

// MutationNode represents a mutation transformation
type MutationNode struct {
	ID           string
	Type         string // "path", "header", "encoding", "transport", "session"
	Name         string
	Description  string
	Capabilities []string
}

// MutationEdge represents a dependency between mutations
type MutationEdge struct {
	From string
	To   string
	Weight float64
}

// MutationGraph represents a dependency graph of mutations
type MutationGraph struct {
	nodes map[string]*MutationNode
	edges []*MutationEdge
	mu    sync.RWMutex
}

// NewMutationGraph creates a new mutation graph
func NewMutationGraph() *MutationGraph {
	return &MutationGraph{
		nodes: make(map[string]*MutationNode),
		edges: make([]*MutationEdge, 0),
	}
}

// AddNode adds a mutation node to the graph
func (g *MutationGraph) AddNode(node *MutationNode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[node.ID]; exists {
		return fmt.Errorf("node already exists: %s", node.ID)
	}

	g.nodes[node.ID] = node
	return nil
}

// AddEdge adds a dependency edge between nodes
func (g *MutationGraph) AddEdge(from, to string, weight float64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.nodes[from]; !ok {
		return fmt.Errorf("from node not found: %s", from)
	}
	if _, ok := g.nodes[to]; !ok {
		return fmt.Errorf("to node not found: %s", to)
	}

	g.edges = append(g.edges, &MutationEdge{
		From:   from,
		To:     to,
		Weight: weight,
	})

	return nil
}

// GetNode retrieves a node by ID
func (g *MutationGraph) GetNode(id string) (*MutationNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[id]
	return node, ok
}

// GetNodes returns all nodes
func (g *MutationGraph) GetNodes() []*MutationNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*MutationNode, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetEdges returns all edges
func (g *MutationGraph) GetEdges() []*MutationEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := make([]*MutationEdge, len(g.edges))
	copy(edges, g.edges)
	return edges
}

// GetDependencies returns dependencies of a node
func (g *MutationGraph) GetDependencies(nodeID string) []*MutationNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var dependencies []*MutationNode
	for _, edge := range g.edges {
		if edge.From == nodeID {
			if node, ok := g.nodes[edge.To]; ok {
				dependencies = append(dependencies, node)
			}
		}
	}
	return dependencies
}

// GetDependents returns nodes that depend on this node
func (g *MutationGraph) GetDependents(nodeID string) []*MutationNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var dependents []*MutationNode
	for _, edge := range g.edges {
		if edge.To == nodeID {
			if node, ok := g.nodes[edge.From]; ok {
				dependents = append(dependents, node)
			}
		}
	}
	return dependents
}

// BuildPipeline builds a mutation pipeline from nodes
func (g *MutationGraph) BuildPipeline(startNodeID string) ([]*MutationNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.nodes[startNodeID]; !ok {
		return nil, fmt.Errorf("start node not found: %s", startNodeID)
	}

	visited := make(map[string]bool)
	pipeline := make([]*MutationNode, 0)

	var dfs func(nodeID string) error
	dfs = func(nodeID string) error {
		if visited[nodeID] {
			return nil
		}
		visited[nodeID] = true

		if node, ok := g.nodes[nodeID]; ok {
			pipeline = append(pipeline, node)
		}

		// Visit dependencies
		for _, edge := range g.edges {
			if edge.From == nodeID {
				if err := dfs(edge.To); err != nil {
					return err
				}
			}
		}

		return nil
	}

	if err := dfs(startNodeID); err != nil {
		return nil, err
	}

	return pipeline, nil
}

// GetNodesByType returns nodes of a specific type
func (g *MutationGraph) GetNodesByType(nodeType string) []*MutationNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var nodes []*MutationNode
	for _, node := range g.nodes {
		if node.Type == nodeType {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// HasCycle checks if the graph has cycles
func (g *MutationGraph) HasCycle() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	var dfs func(nodeID string) bool
	dfs = func(nodeID string) bool {
		visited[nodeID] = true
		recursionStack[nodeID] = true

		for _, edge := range g.edges {
			if edge.From == nodeID {
				if !visited[edge.To] {
					if dfs(edge.To) {
						return true
					}
				} else if recursionStack[edge.To] {
					return true
				}
			}
		}

		recursionStack[nodeID] = false
		return false
	}

	for nodeID := range g.nodes {
		if !visited[nodeID] {
			if dfs(nodeID) {
				return true
			}
		}
	}

	return false
}

// TopologicalSort returns nodes in topological order
func (g *MutationGraph) TopologicalSort() ([]*MutationNode, error) {
	if g.HasCycle() {
		return nil, fmt.Errorf("graph has cycles")
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	inDegree := make(map[string]int)
	for nodeID := range g.nodes {
		inDegree[nodeID] = 0
	}

	for _, edge := range g.edges {
		inDegree[edge.To]++
	}

	queue := make([]*MutationNode, 0)
	for nodeID, degree := range inDegree {
		if degree == 0 {
			if node, ok := g.nodes[nodeID]; ok {
				queue = append(queue, node)
			}
		}
	}

	result := make([]*MutationNode, 0)
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		for _, edge := range g.edges {
			if edge.From == node.ID {
				inDegree[edge.To]--
				if inDegree[edge.To] == 0 {
					if dependent, ok := g.nodes[edge.To]; ok {
						queue = append(queue, dependent)
					}
				}
			}
		}
	}

	if len(result) != len(g.nodes) {
		return nil, fmt.Errorf("topological sort failed - cycle detected")
	}

	return result, nil
}

// Compose creates a composed mutation from a pipeline
type ComposedMutation struct {
	Steps []*MutationNode
}

// ComposePipeline composes multiple mutations into a pipeline
func (g *MutationGraph) ComposePipeline(nodeIDs []string) (*ComposedMutation, error) {
	var steps []*MutationNode

	for _, nodeID := range nodeIDs {
		node, ok := g.nodes[nodeID]
		if !ok {
			return nil, fmt.Errorf("node not found: %s", nodeID)
		}
		steps = append(steps, node)
	}

	return &ComposedMutation{Steps: steps}, nil
}

// GetStatistics returns graph statistics
func (g *MutationGraph) GetStatistics() GraphStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := GraphStats{
		NodeCount: len(g.nodes),
		EdgeCount: len(g.edges),
		ByType:    make(map[string]int),
	}

	for _, node := range g.nodes {
		stats.ByType[node.Type]++
	}

	return stats
}

// GraphStats represents graph statistics
type GraphStats struct {
	NodeCount int
	EdgeCount int
	ByType    map[string]int
}

// Clone creates a copy of the graph
func (g *MutationGraph) Clone() *MutationGraph {
	g.mu.RLock()
	defer g.mu.RUnlock()

	clone := NewMutationGraph()

	// Clone nodes
	for id, node := range g.nodes {
		clone.nodes[id] = &MutationNode{
			ID:           node.ID,
			Type:         node.Type,
			Name:         node.Name,
			Description:  node.Description,
			Capabilities: append([]string{}, node.Capabilities...),
		}
	}

	// Clone edges
	for _, edge := range g.edges {
		clone.edges = append(clone.edges, &MutationEdge{
			From:   edge.From,
			To:     edge.To,
			Weight: edge.Weight,
		})
	}

	return clone
}
