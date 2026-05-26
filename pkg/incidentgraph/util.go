package incidentgraph

// util.go — small helpers used by engine.go + intent.go.

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

func appendUnique(slice []string, v string) []string {
	if v == "" {
		return slice
	}
	for _, x := range slice {
		if x == v {
			return slice
		}
	}
	return append(slice, v)
}

func appendUniqueUint64(slice []uint64, v uint64) []uint64 {
	if v == 0 {
		return slice
	}
	for _, x := range slice {
		if x == v {
			return slice
		}
	}
	return append(slice, v)
}

func appendBounded(slice []EvidenceRef, ref EvidenceRef) []EvidenceRef {
	slice = append(slice, ref)
	if len(slice) > maxEvidencePerIncident {
		// Keep the newest N entries; oldest are pushed out.
		slice = slice[len(slice)-maxEvidencePerIncident:]
	}
	return slice
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
