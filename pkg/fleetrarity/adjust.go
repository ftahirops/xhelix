package fleetrarity

// Rarity is the cohort-rarity verdict for one (binary, endpoint).
type Rarity struct {
	Known      bool // false = no usable answer (hub down / cohort too small) → no effect
	Rare       bool // true = endpoint seen on few cohort peers (suspicious)
	CohortSize int  // hosts in the cohort (TotalHosts from the hub)
}

const fleetRareBonus = 40   // verdict-engine doc: "Fleet-rare destination +40"
const maxSignalWeight = 200 // mirrors lineagescore cap

// FleetWeightAdjust raises a signal's evidence weight when its behavior
// is rare across the host's cohort. Unknown rarity (hub unreachable or
// cohort below the statistically-meaningful minimum) leaves the weight
// unchanged — fleet rarity is advisory weak evidence, never a standalone
// trigger. v1 is conservative: rare boosts, common is neutral (no -30
// reduction — silencing fleet-common behavior is unsafe until clean-peer
// rarity exists; see the plan's flagged follow-ups).
func FleetWeightAdjust(base int, r Rarity) int {
	w := base
	if r.Known && r.Rare {
		w += fleetRareBonus
	}
	if w > maxSignalWeight {
		w = maxSignalWeight
	}
	return w
}
