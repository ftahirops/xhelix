package web

import (
	"html/template"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

// TestAlertsTemplate_RendersViewChain parses the real template set and
// renders the alerts + dashboard pages, asserting the P6 "View chain"
// affordance (chain-link) is emitted only for alerts carrying a PID.
func TestAlertsTemplate_RendersViewChain(t *testing.T) {
	tpl := template.Must(template.New("ent").Funcs(funcs()).Parse(entTemplates))
	data := map[string]any{
		"Title": "Alerts", "Active": "alerts",
		"Sessions": []SessionView{},
		"Bans":     []BanView{},
		"Stats":    DashboardStats{},
		"Alerts": []model.Alert{
			{RuleID: "redzone_exec", Reason: "blocked", Event: model.Event{PID: 4821, Comm: "bash"}},
			{RuleID: "noproc", Reason: "x", Event: model.Event{PID: 0, Comm: "kernel"}},
		},
	}
	hasChainCall := func(out, pid string) bool {
		for i := 0; ; {
			j := strings.Index(out[i:], "viewChain(")
			if j < 0 {
				return false
			}
			i += j
			seg := out[i : i+30]
			if strings.Contains(seg, pid) {
				return true
			}
			i += len("viewChain(")
		}
	}

	var sb strings.Builder
	if err := tpl.ExecuteTemplate(&sb, "alerts", data); err != nil {
		t.Fatalf("render alerts: %v", err)
	}
	out := sb.String()
	if !hasChainCall(out, "4821") {
		t.Error("alerts row with PID should emit viewChain(4821)")
	}
	// One <a class="chain-link"> — the PID-0 row is excluded by {{if .Event.PID}}.
	if n := strings.Count(out, `class="chain-link"`); n != 1 {
		t.Errorf("expected exactly 1 chain-link (PID 0 excluded), got %d", n)
	}
	if !strings.Contains(out, `id="chainModal"`) {
		t.Error("chain modal markup missing from footer")
	}

	var db strings.Builder
	data["Active"] = "dashboard"
	if err := tpl.ExecuteTemplate(&db, "dashboard", data); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	if !hasChainCall(db.String(), "4821") {
		t.Error("dashboard recent-alerts should emit viewChain for a PID")
	}
}
