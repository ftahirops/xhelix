package xhubfleet

import (
	"sync"

	"github.com/xhelix/xhelix/pkg/baselinehub"
)

// RarityIndex is the cohort-aware index of who-does-what across the fleet.
// Built from all uploaded windows. Rebuild periodically (e.g. every 15 min)
// from the persisted Upload corpus.
type RarityIndex struct {
	mu      sync.RWMutex
	cohorts map[string]*Cohort // CohortKey.String() → cohort
}

func NewRarityIndex() *RarityIndex {
	return &RarityIndex{cohorts: map[string]*Cohort{}}
}

// Ingest folds one Upload into the matching cohort. Idempotent for the
// same (host, window-time) tuple if you Reset between rebuilds.
func (r *RarityIndex) Ingest(u baselinehub.Upload) {
	if len(u.Windows) == 0 {
		return
	}
	key := FromTags(u.Cohort)
	keyStr := key.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.cohorts[keyStr]
	if c == nil {
		c = newCohort(key)
		r.cohorts[keyStr] = c
	}
	for _, w := range u.Windows {
		if w == nil {
			continue
		}
		c.AddWindow(u.HostTag, w)
	}
}

// Reset clears all indexed data. Call before Ingest-loop rebuild.
func (r *RarityIndex) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cohorts = map[string]*Cohort{}
}

// Cohort returns the Cohort for a key, or nil if absent.
func (r *RarityIndex) Cohort(k CohortKey) *Cohort {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cohorts[k.String()]
}

// Cohorts returns all cohort keys currently indexed.
func (r *RarityIndex) Cohorts() []CohortKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CohortKey, 0, len(r.cohorts))
	for _, c := range r.cohorts {
		out = append(out, c.Key)
	}
	return out
}

// RarityFraction returns the share of hosts in `c` that have seen
// (binary, feature) for the given feature-class. 0 = first-seen
// (peer-rare); 1 = ubiquitous. Returns 0 if the binary or feature
// isn't indexed.
func (c *Cohort) RarityFraction(class FeatureClass, binary, feature string) float64 {
	if c == nil {
		return 0
	}
	hosts := c.HostCount()
	if hosts == 0 {
		return 0
	}
	idx := c.classIndex(class)
	bm := idx[binary]
	if bm == nil {
		return 0
	}
	return float64(bm[feature]) / float64(hosts)
}

// FeatureClass selects which per-binary feature dimension to query.
type FeatureClass int

const (
	ClassChild FeatureClass = iota
	ClassEndpoint
	ClassFileWrite
	ClassSensitive
	ClassBinarySHA
	ClassListenPort
)

func (c *Cohort) classIndex(cl FeatureClass) map[string]map[string]int {
	switch cl {
	case ClassChild:
		return c.BinaryChildren
	case ClassEndpoint:
		return c.BinaryEndpoints
	case ClassFileWrite:
		return c.BinaryFileWrites
	case ClassSensitive:
		return c.BinarySensitive
	case ClassBinarySHA:
		return c.BinarySHAs
	case ClassListenPort:
		return c.BinaryListenPorts
	}
	return nil
}
