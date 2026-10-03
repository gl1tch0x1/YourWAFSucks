package clustering

import (
	"math"
	"sort"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Cluster represents a group of similar responses
type Cluster struct {
	ID          string
	Responses   []*httpclient.Response
	Count       int
	ClusterType string
	Representative *httpclient.Response
	Similarity  float64
}

// Clusterer performs response clustering
type Clusterer struct {
	config Config
}

// Config holds clustering configuration
type Config struct {
	SimilarityThreshold float64
	MaxClusters         int
	MinClusterSize      int
}

// New creates a new clusterer
func New(cfg Config) *Clusterer {
	if cfg.SimilarityThreshold == 0 {
		cfg.SimilarityThreshold = 0.85
	}
	if cfg.MaxClusters == 0 {
		cfg.MaxClusters = 50
	}
	if cfg.MinClusterSize == 0 {
		cfg.MinClusterSize = 2
	}
	return &Clusterer{config: cfg}
}

// Cluster groups similar responses together
func (c *Clusterer) Cluster(responses []*httpclient.Response) []*Cluster {
	if len(responses) == 0 {
		return []*Cluster{}
	}

	clusters := []*Cluster{}
	assigned := make([]bool, len(responses))

	for i, resp := range responses {
		if assigned[i] {
			continue
		}

		// Create new cluster with this response as representative
		cluster := &Cluster{
			ID:          generateClusterID(len(clusters)),
			Responses:   []*httpclient.Response{resp},
			Count:       1,
			Representative: resp,
		}

		assigned[i] = true

		// Find similar responses
		for j := i + 1; j < len(responses); j++ {
			if assigned[j] {
				continue
			}

			sim := c.calculateSimilarity(resp, responses[j])
			if sim >= c.config.SimilarityThreshold {
				cluster.Responses = append(cluster.Responses, responses[j])
				cluster.Count++
				assigned[j] = true
			}
		}

		// Calculate cluster similarity
		if cluster.Count > 1 {
			cluster.Similarity = c.calculateClusterSimilarity(cluster)
		}

		// Determine cluster type
		cluster.ClusterType = c.determineClusterType(cluster)

		clusters = append(clusters, cluster)
	}

	// Filter small clusters
	var filtered []*Cluster
	for _, cluster := range clusters {
		if cluster.Count >= c.config.MinClusterSize {
			filtered = append(filtered, cluster)
		}
	}

	// Sort by size (largest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Count > filtered[j].Count
	})

	// Limit number of clusters
	if len(filtered) > c.config.MaxClusters {
		filtered = filtered[:c.config.MaxClusters]
	}

	return filtered
}

// calculateSimilarity computes similarity between two responses
func (c *Clusterer) calculateSimilarity(r1, r2 *httpclient.Response) float64 {
	sim := 0.0
	weight := 0.0

	// Status similarity (40% weight)
	if r1.Status == r2.Status {
		sim += 0.4
	}
	weight += 0.4

	// Body similarity (40% weight)
	bodySim := calculateBodySimilarity(r1.Body, r2.Body)
	sim += bodySim * 0.4
	weight += 0.4

	// Size similarity (10% weight)
	sizeSim := calculateSizeSimilarity(len(r1.Body), len(r2.Body))
	sim += sizeSim * 0.1
	weight += 0.1

	// Header similarity (10% weight)
	headerSim := calculateHeaderSimilarity(r1.Headers, r2.Headers)
	sim += headerSim * 0.1
	weight += 0.1

	if weight > 0 {
		return sim / weight
	}
	return 0.0
}

// calculateClusterSimilarity computes average similarity within a cluster
func (c *Clusterer) calculateClusterSimilarity(cluster *Cluster) float64 {
	if cluster.Count <= 1 {
		return 1.0
	}

	totalSim := 0.0
	comparisons := 0

	for i := 0; i < cluster.Count; i++ {
		for j := i + 1; j < cluster.Count; j++ {
			sim := c.calculateSimilarity(cluster.Responses[i], cluster.Responses[j])
			totalSim += sim
			comparisons++
		}
	}

	if comparisons > 0 {
		return totalSim / float64(comparisons)
	}
	return 0.0
}

// determineClusterType determines the type of cluster
func (c *Clusterer) determineClusterType(cluster *Cluster) string {
	if cluster.Count == 0 {
		return "empty"
	}

	rep := cluster.Representative

	// Check if all responses have the same status
	allSameStatus := true
	for _, resp := range cluster.Responses {
		if resp.Status != rep.Status {
			allSameStatus = false
			break
		}
	}

	if allSameStatus {
		switch rep.Status {
		case 200, 201, 202, 203, 204, 205, 206:
			return "success"
		case 301, 302, 303, 307, 308:
			return "redirect"
		case 400, 401, 403, 404, 405:
			return "authorization"
		case 500, 502, 503, 504:
			return "server_error"
		default:
			return "status_" + string(rune(rep.Status))
		}
	}

	return "mixed"
}

// calculateBodySimilarity computes body similarity
func calculateBodySimilarity(body1, body2 []byte) float64 {
	if len(body1) == 0 && len(body2) == 0 {
		return 1.0
	}
	if len(body1) == 0 || len(body2) == 0 {
		return 0.0
	}

	maxLen := float64(max(len(body1), len(body2)))
	minLen := float64(min(len(body1), len(body2)))
	sizeRatio := minLen / maxLen

	// Byte-level similarity
	minLenInt := min(len(body1), len(body2))
	matches := 0
	for i := 0; i < minLenInt; i++ {
		if body1[i] == body2[i] {
			matches++
		}
	}
	byteSimilarity := float64(matches) / float64(minLenInt)

	return (sizeRatio + byteSimilarity) / 2.0
}

// calculateSizeSimilarity computes size similarity
func calculateSizeSimilarity(size1, size2 int) float64 {
	if size1 == 0 && size2 == 0 {
		return 1.0
	}
	if size1 == 0 || size2 == 0 {
		return 0.0
	}

	maxSize := float64(max(size1, size2))
	minSize := float64(min(size1, size2))
	return minSize / maxSize
}

// calculateHeaderSimilarity computes header similarity
func calculateHeaderSimilarity(headers1, headers2 map[string][]string) float64 {
	if len(headers1) == 0 && len(headers2) == 0 {
		return 1.0
	}

	matches := 0
	total := 0

	for k, v1 := range headers1 {
		total++
		if v2, ok := headers2[k]; ok {
			if compareStringSlices(v1, v2) {
				matches++
			}
		}
	}

	for k := range headers2 {
		if _, ok := headers1[k]; !ok {
			total++
		}
	}

	if total == 0 {
		return 1.0
	}

	return float64(matches) / float64(total)
}

// generateClusterID generates a unique cluster ID
func generateClusterID(index int) string {
	clusterTypes := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
	if index < len(clusterTypes) {
		return clusterTypes[index]
	}
	return "CLUSTER-" + string(rune(index))
}

// compareStringSlices compares string slices
func compareStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Summary provides a summary of clustering results
type Summary struct {
	TotalResponses int
	TotalClusters  int
	ClustersByType map[string]int
	LargestCluster  int
	SmallestCluster int
}

// Summarize creates a summary of clustering results
func (c *Clusterer) Summarize(clusters []*Cluster) Summary {
	totalResponses := 0
	clustersByType := make(map[string]int)
	largest := 0
	smallest := math.MaxInt32

	for _, cluster := range clusters {
		totalResponses += cluster.Count
		clustersByType[cluster.ClusterType]++
		if cluster.Count > largest {
			largest = cluster.Count
		}
		if cluster.Count < smallest {
			smallest = cluster.Count
		}
	}

	if smallest == math.MaxInt32 {
		smallest = 0
	}

	return Summary{
		TotalResponses: totalResponses,
		TotalClusters:  len(clusters),
		ClustersByType: clustersByType,
		LargestCluster:  largest,
		SmallestCluster: smallest,
	}
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
