package lineagescore

import "testing"

func TestSensitivityBoost(t *testing.T) {
	cases := []struct {
		name string
		base int
		tags map[string]string
		want int
	}{
		{"nil tags unchanged", 50, nil, 50},
		{"empty tags unchanged", 50, map[string]string{}, 50},
		{"clean taint unchanged", 50, map[string]string{"secret_taint": "clean"}, 50},
		{"unknown taint unchanged", 50, map[string]string{"secret_taint": "unknown"}, 50},
		{"non-sensitive asset_class unchanged", 50, map[string]string{"asset_class": "log_sink"}, 50},
		{"config asset_class unchanged", 50, map[string]string{"asset_class": "config"}, 50},

		// secret_touched / outbound_restricted double the base.
		{"secret_touched doubles", 50, map[string]string{"secret_taint": "secret_touched"}, 100},
		{"outbound_restricted doubles", 50, map[string]string{"secret_taint": "outbound_restricted"}, 100},
		// containment_required triples.
		{"containment_required triples", 50, map[string]string{"secret_taint": "containment_required"}, 150},

		// sensitive asset_class adds +40 (each of the real 9).
		{"secret_file +40", 50, map[string]string{"asset_class": "secret_file"}, 90},
		{"credential_store +40", 50, map[string]string{"asset_class": "credential_store"}, 90},
		{"persistence_surface +40", 20, map[string]string{"asset_class": "persistence_surface"}, 60},
		{"metadata_endpoint +40", 20, map[string]string{"asset_class": "metadata_endpoint"}, 60},

		// stacking: taint multiplier applies to base, THEN +40 for sensitive class.
		{"secret_touched + secret_file", 50, map[string]string{"secret_taint": "secret_touched", "asset_class": "secret_file"}, 140},
		// cap at 200.
		{"cap 200 via containment", 80, map[string]string{"secret_taint": "containment_required"}, 200},
		{"cap 200 via stack", 90, map[string]string{"secret_taint": "containment_required", "asset_class": "secret_file"}, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SensitivityBoost(c.base, c.tags); got != c.want {
				t.Fatalf("SensitivityBoost(%d,%v)=%d want %d", c.base, c.tags, got, c.want)
			}
		})
	}
}

func TestVerdictTier(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "none"}, {39, "none"}, {40, "watch"}, {79, "watch"},
		{80, "high"}, {119, "high"}, {120, "critical"}, {500, "critical"},
	}
	for _, c := range cases {
		if got := Tier(c.score); got != c.want {
			t.Fatalf("Tier(%d)=%q want %q", c.score, got, c.want)
		}
	}
}
