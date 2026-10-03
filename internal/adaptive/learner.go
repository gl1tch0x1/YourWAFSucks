package adaptive

import (
	"encoding/json"
	"os"
	"sort"
	"sync"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// Stat summarizes the observed outcomes for a single technique.
type Stat struct {
	Attempts   int     `json:"attempts"`
	Findings   int     `json:"findings"`
	TotalScore int     `json:"total_score"`
	AvgScore   float64 `json:"avg_score"`
	Weight     float64 `json:"weight"`
}

// Learner tracks per-technique effectiveness and reprioritizes payloads
// based on the outcomes it has observed. It is safe for concurrent use.
type Learner struct {
	mu    sync.RWMutex
	stats map[string]Stat
	prior float64
	alpha float64
}

const (
	defaultPrior = 0.5
	defaultAlpha = 2.0
)

// NewLearner returns an empty learner with a neutral prior for unseen techniques.
func NewLearner() *Learner {
	return &Learner{
		stats: make(map[string]Stat),
		prior: defaultPrior,
		alpha: defaultAlpha,
	}
}

// Record folds one observed attempt for a technique into the learner. A finding
// marks the attempt as successful, score is the 0-100 result and weight is the
// optional technique weight used for downstream prioritization.
func (l *Learner) Record(technique string, finding bool, score int, weight float64) {
	if technique == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.stats[technique]
	st.Attempts++
	if finding {
		st.Findings++
	}
	st.TotalScore += score
	st.AvgScore = float64(st.TotalScore) / float64(st.Attempts)
	if weight > 0 {
		st.Weight = weight
	}
	l.stats[technique] = st
}

// Score returns the smoothed effectiveness of a technique in [0,1]. Techniques
// without observations receive the neutral prior.
func (l *Learner) Score(technique string) float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.scoreLocked(technique)
}

func (l *Learner) scoreLocked(technique string) float64 {
	st, ok := l.stats[technique]
	if !ok || st.Attempts == 0 {
		return l.prior
	}
	// Laplace-smoothed success rate, pulled toward the prior.
	success := (float64(st.Findings) + l.alpha*l.prior) / (float64(st.Attempts) + l.alpha)
	avg := clamp01(st.AvgScore / 100.0)
	return clamp01(0.6*success + 0.4*avg)
}

// Stats returns a copy of the current per-technique statistics.
func (l *Learner) Stats() map[string]Stat {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make(map[string]Stat, len(l.stats))
	for k, v := range l.stats {
		out[k] = v
	}
	return out
}

// Prioritize returns payloads ordered by descending learned score. The sort is
// stable: payloads with equal scores keep their original relative order.
func (l *Learner) Prioritize(payloads []techniques.Payload) []techniques.Payload {
	out := make([]techniques.Payload, len(payloads))
	copy(out, payloads)

	l.mu.RLock()
	scores := make([]float64, len(out))
	for i := range out {
		scores[i] = l.scoreLocked(out[i].Technique)
	}
	l.mu.RUnlock()

	idx := make([]int, len(out))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return scores[idx[a]] > scores[idx[b]]
	})

	res := make([]techniques.Payload, len(out))
	for i, j := range idx {
		res[i] = out[j]
	}
	return res
}

type snapshot struct {
	Prior float64         `json:"prior"`
	Alpha float64         `json:"alpha"`
	Stats map[string]Stat `json:"stats"`
}

// Save writes the learner state to path as JSON.
func (l *Learner) Save(path string) error {
	l.mu.RLock()
	snap := snapshot{
		Prior: l.prior,
		Alpha: l.alpha,
		Stats: make(map[string]Stat, len(l.stats)),
	}
	for k, v := range l.stats {
		snap.Stats[k] = v
	}
	l.mu.RUnlock()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadLearner reads a learner state previously written by Save.
func LoadLearner(path string) (*Learner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}

	l := NewLearner()
	if snap.Prior > 0 {
		l.prior = snap.Prior
	}
	if snap.Alpha > 0 {
		l.alpha = snap.Alpha
	}
	if snap.Stats != nil {
		l.stats = snap.Stats
	}
	return l, nil
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
