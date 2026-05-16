package iforest

import (
	"math"
	"math/rand"
	"testing"
)

// generateGaussianCloud returns n points around (cx, cy, ...) with
// stddev = 1.0 per axis, using r as the RNG.
func generateGaussianCloud(r *rand.Rand, n, dims int, center []float64) [][]float64 {
	out := make([][]float64, n)
	for i := 0; i < n; i++ {
		v := make([]float64, dims)
		for d := 0; d < dims; d++ {
			c := 0.0
			if d < len(center) {
				c = center[d]
			}
			v[d] = c + r.NormFloat64()
		}
		out[i] = v
	}
	return out
}

func TestEmptyTrainErrors(t *testing.T) {
	if _, err := Train(nil, Config{}); err == nil {
		t.Fatal("Train with empty samples should error")
	}
}

func TestInconsistentFeatureLengthErrors(t *testing.T) {
	samples := [][]float64{{1, 2}, {3}}
	if _, err := Train(samples, Config{}); err == nil {
		t.Fatal("inconsistent vectors should error")
	}
}

func TestNormalPointScoresLow(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	training := generateGaussianCloud(r, 500, 3, []float64{0, 0, 0})
	f, err := Train(training, Config{Seed: 1234})
	if err != nil {
		t.Fatal(err)
	}
	// A point at the centre of the training distribution should
	// score below 0.55.
	s := f.Score([]float64{0, 0, 0})
	if s > 0.55 {
		t.Errorf("centre-of-mass scored anomalous: %f", s)
	}
}

func TestAnomalousPointScoresHigh(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	training := generateGaussianCloud(r, 500, 3, []float64{0, 0, 0})
	f, _ := Train(training, Config{Seed: 1234})
	// A point 20σ off the centroid is unambiguously anomalous.
	s := f.Score([]float64{20, 20, 20})
	if s < 0.6 {
		t.Errorf("far point scored normal: %f", s)
	}
}

func TestAnomalyHigherThanNormal(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	training := generateGaussianCloud(r, 300, 2, []float64{5, 5})
	f, _ := Train(training, Config{Seed: 99})
	normal := f.Score([]float64{5, 5})
	anom := f.Score([]float64{-50, -50})
	if anom <= normal {
		t.Fatalf("anomaly=%f should exceed normal=%f", anom, normal)
	}
}

func TestIsAnomalyDefaultThreshold(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	training := generateGaussianCloud(r, 500, 2, []float64{0, 0})
	f, _ := Train(training, Config{Seed: 99})
	if f.IsAnomaly([]float64{0, 0}, 0) {
		t.Error("centre should not be flagged")
	}
	if !f.IsAnomaly([]float64{100, 100}, 0) {
		t.Error("far outlier should be flagged at default threshold")
	}
}

func TestWrongFeatureLengthScoresZero(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	training := generateGaussianCloud(r, 100, 3, nil)
	f, _ := Train(training, Config{Seed: 1})
	got := f.Score([]float64{1, 2}) // wrong dim
	if got != 0 {
		t.Fatalf("wrong-dim score = %f, want 0", got)
	}
}

func TestTreesCount(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	training := generateGaussianCloud(r, 50, 2, nil)
	f, _ := Train(training, Config{NumTrees: 17, Seed: 1})
	if f.Trees() != 17 {
		t.Fatalf("trees = %d, want 17", f.Trees())
	}
}

func TestFeaturesReported(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	training := generateGaussianCloud(r, 50, 5, nil)
	f, _ := Train(training, Config{Seed: 1})
	if f.Features() != 5 {
		t.Fatalf("features = %d, want 5", f.Features())
	}
}

func TestSubsampleLargerThanSamplesClamped(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	training := generateGaussianCloud(r, 10, 2, nil)
	_, err := Train(training, Config{Subsample: 1000, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSeedReproducibility(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	training := generateGaussianCloud(r, 200, 2, nil)
	f1, _ := Train(training, Config{Seed: 42})
	f2, _ := Train(training, Config{Seed: 42})
	probe := []float64{3, -2}
	if math.Abs(f1.Score(probe)-f2.Score(probe)) > 1e-9 {
		t.Fatalf("seeded scores differ: %f vs %f", f1.Score(probe), f2.Score(probe))
	}
}

func TestCNormBaseCase(t *testing.T) {
	if cNorm(0) != 0 || cNorm(1) != 0 {
		t.Fatal("c(n) for n<=1 must be 0")
	}
	// c(2) = 1.0 by Liu/Ting/Zhou Eq. 1 (approximately)
	v := cNorm(2)
	if v < 0.0 || v > 1.5 {
		t.Errorf("c(2) sanity bound failed: %f", v)
	}
}

func TestConstantFeatureNoSplit(t *testing.T) {
	// Every sample identical → forest still builds, scores ≈ 0.
	training := [][]float64{{1, 1}, {1, 1}, {1, 1}, {1, 1}}
	f, err := Train(training, Config{Seed: 5})
	if err != nil {
		t.Fatal(err)
	}
	// A new point shouldn't crash and should produce a sane score.
	got := f.Score([]float64{1, 1})
	if math.IsNaN(got) || math.IsInf(got, 0) {
		t.Fatalf("constant-feature score = %f", got)
	}
}
