package recorder

import "time"

// AppCoverage summarises the recorder's knowledge about one application.
type AppCoverage struct {
	Shapes       int
	Observations int64
	NewestShape  time.Time
	OldestShape  time.Time
}

// CoverageReport is the aggregate view of all shape rows across apps.
type CoverageReport struct {
	Apps              int
	Shapes            int
	TotalObservations int64
	ByApp             map[string]AppCoverage
}

// Coverage aggregates shape rows into a per-app coverage report. Pure.
func Coverage(rows []ShapeRow) CoverageReport {
	rep := CoverageReport{ByApp: map[string]AppCoverage{}}
	for _, r := range rows {
		ac := rep.ByApp[r.AppID]
		ac.Shapes++
		ac.Observations += r.Count
		if ac.NewestShape.IsZero() || r.LastSeen.After(ac.NewestShape) {
			ac.NewestShape = r.LastSeen
		}
		if ac.OldestShape.IsZero() || r.FirstSeen.Before(ac.OldestShape) {
			ac.OldestShape = r.FirstSeen
		}
		rep.ByApp[r.AppID] = ac
		rep.Shapes++
		rep.TotalObservations += r.Count
	}
	rep.Apps = len(rep.ByApp)
	return rep
}
