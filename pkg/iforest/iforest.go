// Package iforest is a pure-Go isolation forest for behavioural
// anomaly detection on `pkg/baseline` per-binary feature vectors.
//
// Algorithm (Liu, Ting, Zhou 2008 — "Isolation Forest"):
//
//   Training:
//     1. Build N independent random-binary-partition trees.
//     2. For each tree: sample S items from the training set;
//        recursively split by picking a random feature and a
//        random split value between min/max of that feature
//        within the current node; stop at maxDepth = ceil(log2(S))
//        or when only one item remains.
//
//   Scoring a new point:
//     - For each tree, count the path length from root to the
//       leaf the point lands in (longer paths = harder to isolate).
//     - Average the path lengths, normalise against c(S) — the
//       expected path length of an unsuccessful BST search of S
//       items — and convert to a 0..1 anomaly score:
//
//         score = 2^(-avg_path / c(S))
//
//       score near 1.0 = highly anomalous (easy to isolate)
//       score near 0.5 = average
//       score near 0.0 = very normal
//
// No external dependencies (math/rand + math).
package iforest

import (
	"errors"
	"math"
	"math/rand"
	"sync"
)

// Forest is a trained isolation forest.
type Forest struct {
	mu          sync.RWMutex
	trees       []*tree
	subsampleN  int     // S — items each tree was trained on
	cN          float64 // c(S) normalisation constant
	features    int     // expected feature-vector length
}

// tree is one random partition tree.
type tree struct {
	maxDepth int
	root     *node
}

// node is one split (Left+Right both non-nil) or a leaf (both nil).
type node struct {
	// split params (interior nodes)
	feature  int
	thresh   float64
	left     *node
	right    *node

	// leaf-only
	leafSize int // remaining items at this leaf (used by path correction)
	depth    int
}

// Config controls Train.
type Config struct {
	// NumTrees — number of trees in the forest. <=0 uses 100.
	NumTrees int

	// Subsample — items per tree. <=0 uses min(256, len(samples)).
	Subsample int

	// MaxDepth — explicit cap. <=0 uses ceil(log2(Subsample)).
	MaxDepth int

	// Seed — rand seed for reproducibility. 0 picks a random seed.
	Seed int64
}

// Train builds a Forest. Returns an error when samples is empty
// or feature lengths are inconsistent.
func Train(samples [][]float64, cfg Config) (*Forest, error) {
	if len(samples) == 0 {
		return nil, errors.New("iforest: empty training set")
	}
	features := len(samples[0])
	for _, s := range samples {
		if len(s) != features {
			return nil, errors.New("iforest: inconsistent feature-vector length")
		}
	}
	numTrees := cfg.NumTrees
	if numTrees <= 0 {
		numTrees = 100
	}
	sub := cfg.Subsample
	if sub <= 0 {
		sub = 256
	}
	if sub > len(samples) {
		sub = len(samples)
	}
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = int(math.Ceil(math.Log2(float64(sub))))
		if maxDepth < 1 {
			maxDepth = 1
		}
	}
	seed := cfg.Seed
	if seed == 0 {
		seed = rand.Int63()
	}

	f := &Forest{
		trees:      make([]*tree, numTrees),
		subsampleN: sub,
		cN:         cNorm(float64(sub)),
		features:   features,
	}
	for i := 0; i < numTrees; i++ {
		r := rand.New(rand.NewSource(seed + int64(i)))
		idxs := subsampleIndices(r, len(samples), sub)
		f.trees[i] = buildTree(r, samples, idxs, 0, maxDepth, features)
	}
	return f, nil
}

// Score returns the 0..1 anomaly score for the given feature vector.
// Higher = more anomalous. A value ≥ 0.7 is the conventional
// "highly suspicious" threshold; ≥ 0.5 is "above average."
//
// Returns 0 with no error for vectors of the wrong feature length;
// callers should validate via Features().
func (f *Forest) Score(sample []float64) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(sample) != f.features || len(f.trees) == 0 {
		return 0
	}
	var totalPath float64
	for _, t := range f.trees {
		totalPath += t.pathLength(sample)
	}
	avg := totalPath / float64(len(f.trees))
	if f.cN <= 0 {
		return 0
	}
	return math.Pow(2, -avg/f.cN)
}

// IsAnomaly returns true when Score(sample) >= threshold.
// threshold = 0 falls back to 0.6 (conservative high-confidence).
func (f *Forest) IsAnomaly(sample []float64, threshold float64) bool {
	if threshold <= 0 {
		threshold = 0.6
	}
	return f.Score(sample) >= threshold
}

// Trees returns the configured tree count.
func (f *Forest) Trees() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.trees)
}

// Features returns the expected feature-vector length.
func (f *Forest) Features() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.features
}

// ── tree construction & traversal ────────────────────────────

func buildTree(r *rand.Rand, samples [][]float64, idxs []int, depth, maxDepth, features int) *tree {
	t := &tree{maxDepth: maxDepth}
	t.root = buildNode(r, samples, idxs, depth, maxDepth, features)
	return t
}

func buildNode(r *rand.Rand, samples [][]float64, idxs []int, depth, maxDepth, features int) *node {
	// Leaf conditions: depth cap or singleton.
	if depth >= maxDepth || len(idxs) <= 1 {
		return &node{leafSize: len(idxs), depth: depth}
	}
	// Pick a random feature with non-zero range; if every feature
	// is constant at this node, terminate as leaf.
	tried := make(map[int]bool, features)
	for attempts := 0; attempts < features; attempts++ {
		f := r.Intn(features)
		if tried[f] {
			continue
		}
		tried[f] = true
		mn, mx := minmax(samples, idxs, f)
		if mn == mx {
			continue
		}
		thresh := mn + r.Float64()*(mx-mn)
		left := make([]int, 0, len(idxs)/2)
		right := make([]int, 0, len(idxs)/2)
		for _, i := range idxs {
			if samples[i][f] < thresh {
				left = append(left, i)
			} else {
				right = append(right, i)
			}
		}
		// If split was degenerate (all on one side), try another feature.
		if len(left) == 0 || len(right) == 0 {
			continue
		}
		return &node{
			feature: f, thresh: thresh, depth: depth,
			left:  buildNode(r, samples, left, depth+1, maxDepth, features),
			right: buildNode(r, samples, right, depth+1, maxDepth, features),
		}
	}
	return &node{leafSize: len(idxs), depth: depth}
}

// pathLength returns the path length from root for `sample`.
// At a leaf with leafSize>1, we add c(leafSize) — the expected
// remaining isolation depth — as Liu/Ting/Zhou recommend.
func (t *tree) pathLength(sample []float64) float64 {
	n := t.root
	for n != nil && n.left != nil && n.right != nil {
		if sample[n.feature] < n.thresh {
			n = n.left
		} else {
			n = n.right
		}
	}
	if n == nil {
		return 0
	}
	depth := float64(n.depth)
	if n.leafSize > 1 {
		depth += cNorm(float64(n.leafSize))
	}
	return depth
}

// cNorm returns c(n), the expected path length of an unsuccessful
// search in a BST of n items. Liu/Ting/Zhou Eq. 1.
//   c(n) = 2 * H(n-1) - 2*(n-1)/n   where H(i) = ln(i) + γ
func cNorm(n float64) float64 {
	if n <= 1 {
		return 0
	}
	const eulerMascheroni = 0.5772156649
	hn1 := math.Log(n-1) + eulerMascheroni
	return 2*hn1 - 2*(n-1)/n
}

// minmax returns the smallest and largest value of feature `f`
// across the indexed subset.
func minmax(samples [][]float64, idxs []int, f int) (float64, float64) {
	mn := samples[idxs[0]][f]
	mx := mn
	for _, i := range idxs[1:] {
		v := samples[i][f]
		if v < mn {
			mn = v
		}
		if v > mx {
			mx = v
		}
	}
	return mn, mx
}

// subsampleIndices returns up to k random indices from [0,n).
func subsampleIndices(r *rand.Rand, n, k int) []int {
	if k >= n {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	}
	// Reservoir sampling
	out := make([]int, k)
	for i := 0; i < k; i++ {
		out[i] = i
	}
	for i := k; i < n; i++ {
		j := r.Intn(i + 1)
		if j < k {
			out[j] = i
		}
	}
	return out
}
