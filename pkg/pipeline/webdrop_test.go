package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/brp/writerattr"
	"github.com/xhelix/xhelix/pkg/model"
)

// TestWebDropFIM_UploadsPhp proves that a FIM create event for a PHP file
// inside wp-content/uploads/ fires webdrop.php_drop at Critical severity.
// This is the newbikebox attack shape: php-fpm writes a webshell to uploads/.
func TestWebDropFIM_UploadsPhp(t *testing.T) {
	var got []model.Alert
	p := &Pipeline{
		Emit: func(a model.Alert) { got = append(got, a) },
	}

	ev := model.NewEvent("fim", model.SeverityHigh)
	ev.Host = "test.host"
	ev.Time = time.Now()
	ev.Tags["path"] = "/var/www/vhosts/example.com/httpdocs/wp-content/uploads/jC88R3.php"
	ev.Tags["create"] = "true"

	p.Handle(context.Background(), ev)

	var drop *model.Alert
	for i := range got {
		if got[i].RuleID == "webdrop.php_drop" {
			drop = &got[i]
			break
		}
	}
	if drop == nil {
		t.Fatal("expected webdrop.php_drop alert, got none")
	}
	if drop.Event.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical", drop.Event.Severity)
	}
	if drop.Event.Tags["path"] == "" {
		t.Error("path tag missing on alert")
	}
}

// TestWebDropFIM_WriterCacheAttribution proves that when BRPWriterCache
// has a recent php-fpm write to the same path, the actor comm is recovered
// and the alert carries the web-worker context.
func TestWebDropFIM_WriterCacheAttribution(t *testing.T) {
	var got []model.Alert
	cache := writerattr.NewCache(100, 10*time.Second)
	filePath := "/var/www/vhosts/example.com/httpdocs/wp-content/mu-plugins/evil.php"
	now := time.Now()
	cache.Record(filePath, writerattr.Writer{
		PID:     12345,
		Comm:    "php-fpm",
		ExePath: "/usr/sbin/php-fpm8.3",
		When:    now.Add(-500 * time.Millisecond),
	})

	p := &Pipeline{
		Emit:            func(a model.Alert) { got = append(got, a) },
		BRPWriterCache:  cache,
	}

	ev := model.NewEvent("fim", model.SeverityHigh)
	ev.Time = now
	ev.Tags["path"] = filePath
	ev.Tags["create"] = "true"
	p.Handle(context.Background(), ev)

	var drop *model.Alert
	for i := range got {
		if got[i].RuleID == "webdrop.php_drop" {
			drop = &got[i]
			break
		}
	}
	if drop == nil {
		t.Fatal("expected webdrop.php_drop alert, got none")
	}
	if drop.Event.Comm != "php-fpm" {
		t.Errorf("comm = %q, want php-fpm (writer attribution failed)", drop.Event.Comm)
	}
	if drop.Event.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical (mu-plugins path)", drop.Event.Severity)
	}
}

// TestWebDropFIM_LegitPluginNoAlert proves that a PHP write to a standard
// plugin directory without suspicious naming does NOT fire — prevents FP on
// Plesk/WordPress auto-updaters writing into plugins/.
func TestWebDropFIM_LegitPluginNoAlert(t *testing.T) {
	var got []model.Alert
	p := &Pipeline{
		Emit: func(a model.Alert) { got = append(got, a) },
	}

	ev := model.NewEvent("fim", model.SeverityHigh)
	ev.Tags["path"] = "/var/www/vhosts/example.com/httpdocs/wp-content/plugins/woocommerce/woocommerce.php"
	ev.Tags["write"] = "true"
	p.Handle(context.Background(), ev)

	for _, a := range got {
		if a.RuleID == "webdrop.php_drop" {
			t.Errorf("unexpected webdrop.php_drop on legitimate plugin write: %v", a.Reason)
		}
	}
}
