package adaptive

import (
	"container/heap"
	"math"
	"sort"
)

// Priority represents the priority of a test case
type Priority struct {
	Technique      string
	PayloadID      string
	Score          float64
	TechniqueScore float64
	SignalStrength float64
	Stability      float64
}

// PriorityQueue implements a priority queue for test cases
type PriorityQueue []*Priority

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].Score > pq[j].Score // Higher score = higher priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*Priority)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

// AdaptiveEngine implements adaptive test prioritization
type AdaptiveEngine struct {
	techniqueSuccessRates map[string]float64
	techniqueScores       map[string]float64
	signalWeights         map[string]float64
	minSuccessRate        float64
}

// NewAdaptiveEngine creates a new adaptive engine
func NewAdaptiveEngine() *AdaptiveEngine {
	return &AdaptiveEngine{
		techniqueSuccessRates: make(map[string]float64),
		techniqueScores:       make(map[string]float64),
		signalWeights: map[string]float64{
			"status_delta":   0.4,
			"body_delta":     0.3,
			"timing_delta":   0.1,
			"size_delta":     0.1,
			"redirect_delta": 0.05,
			"header_delta":   0.05,
		},
		minSuccessRate: 0.1, // 10% minimum success rate to keep technique alive
	}
}

// Prioritize prioritizes test cases based on observed effectiveness
func (e *AdaptiveEngine) Prioritize(tests []*Priority) []*Priority {
	// Sort by score
	sort.Slice(tests, func(i, j int) bool {
		return tests[i].Score > tests[j].Score
	})

	return tests
}

// UpdateTechniqueSuccess updates the success rate of a technique
func (e *AdaptiveEngine) UpdateTechniqueSuccess(technique string, success bool) {
	if _, ok := e.techniqueSuccessRates[technique]; !ok {
		e.techniqueSuccessRates[technique] = 0.5 // Start with 50%
	}

	// Exponential moving average
	current := e.techniqueSuccessRates[technique]
	alpha := 0.2
	if success {
		e.techniqueSuccessRates[technique] = current + alpha*(1.0-current)
	} else {
		e.techniqueSuccessRates[technique] = current + alpha*(0.0-current)
	}
}

// CalculatePriority calculates the priority of a test case
func (e *AdaptiveEngine) CalculatePriority(technique string, signals map[string]float64, stability float64) float64 {
	score := 0.0

	// Base technique score
	techniqueScore := e.techniqueScores[technique]
	if techniqueScore == 0 {
		techniqueScore = 0.5 // Default
	}
	score += techniqueScore * 0.3

	// Signal strength
	signalScore := 0.0
	for signal, weight := range e.signalWeights {
		if value, ok := signals[signal]; ok {
			signalScore += value * weight
		}
	}
	score += signalScore * 0.5

	// Stability
	score += stability * 0.2

	return score
}

// GetTechniquePriority returns the priority of a technique
func (e *AdaptiveEngine) GetTechniquePriority(technique string) float64 {
	if rate, ok := e.techniqueSuccessRates[technique]; ok {
		return rate
	}
	return 0.5
}

// DeprioritizeFailedTechniques deprioritizes techniques with low success rates
func (e *AdaptiveEngine) DeprioritizeFailedTechniques(techniques []string) []string {
	var prioritized []string
	var deprioritized []string

	for _, technique := range techniques {
		rate := e.GetTechniquePriority(technique)
		if rate >= e.minSuccessRate {
			prioritized = append(prioritized, technique)
		} else {
			deprioritized = append(deprioritized, technique)
		}
	}

	// Return prioritized first, deprioritized last
	return append(prioritized, deprioritized...)
}

// PrioritizeNearbyMutations prioritizes mutations similar to successful ones
func (e *AdaptiveEngine) PrioritizeNearbyMutations(successfulTechnique string, allTechniques []string) []string {
	// Simple heuristic: prioritize techniques with similar names
	var nearby []string
	var others []string

	successPrefix := getTechniquePrefix(successfulTechnique)

	for _, technique := range allTechniques {
		if technique == successfulTechnique {
			continue
		}
		prefix := getTechniquePrefix(technique)
		if prefix == successPrefix {
			nearby = append(nearby, technique)
		} else {
			others = append(others, technique)
		}
	}

	return append(nearby, others...)
}

// GetStatistics returns adaptive engine statistics
func (e *AdaptiveEngine) GetStatistics() AdaptiveStats {
	stats := AdaptiveStats{
		TechniqueCount:     len(e.techniqueSuccessRates),
		AverageSuccessRate: 0.0,
		BestTechnique:      "",
		BestSuccessRate:    0.0,
		WorstTechnique:     "",
		WorstSuccessRate:   1.0,
	}

	if len(e.techniqueSuccessRates) == 0 {
		return stats
	}

	total := 0.0
	for technique, rate := range e.techniqueSuccessRates {
		total += rate
		if rate > stats.BestSuccessRate {
			stats.BestSuccessRate = rate
			stats.BestTechnique = technique
		}
		if rate < stats.WorstSuccessRate {
			stats.WorstSuccessRate = rate
			stats.WorstTechnique = technique
		}
	}

	stats.AverageSuccessRate = total / float64(len(e.techniqueSuccessRates))

	return stats
}

// AdaptiveStats represents adaptive engine statistics
type AdaptiveStats struct {
	TechniqueCount     int
	AverageSuccessRate float64
	BestTechnique      string
	BestSuccessRate    float64
	WorstTechnique     string
	WorstSuccessRate   float64
}

// getTechniquePrefix extracts the prefix of a technique name
func getTechniquePrefix(technique string) string {
	parts := splitTechniqueName(technique)
	if len(parts) > 0 {
		return parts[0]
	}
	return technique
}

// splitTechniqueName splits a technique name into parts
func splitTechniqueName(technique string) []string {
	// Simple split by common separators
	// This is a simplified implementation
	return []string{technique}
}

// OptimizeSignalWeights optimizes signal weights based on effectiveness
func (e *AdaptiveEngine) OptimizeSignalWeights(signalEffectiveness map[string]float64) {
	total := 0.0
	for _, effectiveness := range signalEffectiveness {
		total += effectiveness
	}

	if total == 0 {
		return
	}

	// Normalize weights
	for signal, effectiveness := range signalEffectiveness {
		e.signalWeights[signal] = effectiveness / total
	}
}

// GetSignalWeights returns current signal weights
func (e *AdaptiveEngine) GetSignalWeights() map[string]float64 {
	weights := make(map[string]float64)
	for k, v := range e.signalWeights {
		weights[k] = v
	}
	return weights
}

// DecayScores gradually decays technique scores to favor recent observations
func (e *AdaptiveEngine) DecayScores(decayFactor float64) {
	for technique := range e.techniqueScores {
		e.techniqueScores[technique] *= decayFactor
	}
}

// Reset resets the adaptive engine
func (e *AdaptiveEngine) Reset() {
	e.techniqueSuccessRates = make(map[string]float64)
	e.techniqueScores = make(map[string]float64)
}

// CreatePriorityQueue creates a priority queue from priorities
func CreatePriorityQueue(priorities []*Priority) *PriorityQueue {
	pq := make(PriorityQueue, len(priorities))
	copy(pq, priorities)
	heap.Init(&pq)
	return &pq
}

// RoundRobinPriority implements round-robin with priority weighting
func (e *AdaptiveEngine) RoundRobinPriority(techniques []string, counts map[string]int) string {
	if len(techniques) == 0 {
		return ""
	}

	// Find technique with lowest count
	minCount := math.MaxInt32
	selected := techniques[0]

	for _, technique := range techniques {
		count := counts[technique]
		if count < minCount {
			minCount = count
			selected = technique
		}
	}

	return selected
}
