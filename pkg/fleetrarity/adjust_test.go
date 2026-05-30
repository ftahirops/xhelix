package fleetrarity

import "testing"

func TestFleetWeightAdjust(t *testing.T) {
	cases := []struct {
		name string
		base int
		r    Rarity
		want int
	}{
		{"unknown unchanged", 50, Rarity{Known: false}, 50},
		{"small-cohort unknown unchanged", 50, Rarity{Known: false, CohortSize: 2}, 50},
		{"rare adds 40", 50, Rarity{Known: true, Rare: true, CohortSize: 50}, 90},
		{"common unchanged", 50, Rarity{Known: true, Rare: false, CohortSize: 50}, 50},
		{"rare respects cap 200", 180, Rarity{Known: true, Rare: true, CohortSize: 50}, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FleetWeightAdjust(c.base, c.r); got != c.want {
				t.Fatalf("FleetWeightAdjust(%d,%+v)=%d want %d", c.base, c.r, got, c.want)
			}
		})
	}
}
