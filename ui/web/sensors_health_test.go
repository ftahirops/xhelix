package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// fakeSensor is a minimal sensors.Sensor whose Health() returns a fixed
// drop breakdown, so we can assert the per-sensor health JSON serialization.
type fakeSensor struct {
	name string
	h    sensors.Health
}

func (f *fakeSensor) Name() string                                    { return f.name }
func (f *fakeSensor) Start(context.Context, chan<- model.Event) error { return nil }
func (f *fakeSensor) Stop(context.Context) error                      { return nil }
func (f *fakeSensor) Health() sensors.Health                          { return f.h }

func TestHandleSensorsIncludesDropBreakdown(t *testing.T) {
	s := &Server{Config: Config{
		Sensors: []sensors.Sensor{
			&fakeSensor{
				name: "ebpf",
				h: sensors.Health{
					Healthy:          true,
					DropCount:        6,
					DropRingbuf:      1,
					DropConsumerFull: 2,
					DropDecode:       3,
				},
			},
		},
	}}

	req := httptest.NewRequest("GET", "http://xhelix.local/api/sensors", nil)
	rec := httptest.NewRecorder()
	s.handleSensors(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var out []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, rec.Body.String())
	}
	if len(out) != 1 {
		t.Fatalf("got %d sensors, want 1", len(out))
	}
	entry := out[0]

	for _, k := range []string{"drop_ringbuf", "drop_consumer_full", "drop_decode"} {
		if _, ok := entry[k]; !ok {
			t.Errorf("sensor health JSON missing key %q; got %v", k, entry)
		}
	}

	// JSON numbers decode as float64.
	want := map[string]float64{
		"drop_ringbuf":       1,
		"drop_consumer_full": 2,
		"drop_decode":        3,
		"drop_count":         6,
	}
	for k, v := range want {
		got, ok := entry[k].(float64)
		if !ok {
			t.Errorf("key %q not a number: %v", k, entry[k])
			continue
		}
		if got != v {
			t.Errorf("key %q = %v, want %v", k, got, v)
		}
	}
}
