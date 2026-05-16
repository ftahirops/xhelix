package netids

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// EveRecord is the subset of Suricata's EVE JSON we consume.
//
// Suricata's EVE schema is large; we project to the fields rules
// care about. New event types add new fields here over time.
type EveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	SrcPort   int    `json:"src_port"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	FlowID    int64  `json:"flow_id"`

	Alert *struct {
		Action      string `json:"action"`
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Severity    int    `json:"severity"`
		Category    string `json:"category"`
	} `json:"alert,omitempty"`

	DNS *struct {
		QueryType string `json:"type"`
		Rrname    string `json:"rrname"`
		Rcode     string `json:"rcode"`
	} `json:"dns,omitempty"`

	TLS *struct {
		Version  string `json:"version"`
		SNI      string `json:"sni"`
		JA3      struct{ Hash string } `json:"ja3"`
		JA4      string `json:"ja4"`
	} `json:"tls,omitempty"`
}

// EveTailer reads EVE JSON line-by-line and projects to model.Event.
type EveTailer struct {
	Path string

	closed  atomic.Bool
	lines   atomic.Uint64
	dropped atomic.Uint64
}

// NewEveTailer constructs a tailer for the given EVE path.
func NewEveTailer(path string) *EveTailer { return &EveTailer{Path: path} }

// Run blocks until ctx is cancelled. It opens the file, seeks to
// the end, and tails for new lines, projecting each into out. If
// the file does not exist, Run waits for it to appear (Suricata may
// not have written it yet on first start).
func (t *EveTailer) Run(ctx context.Context, out chan<- model.Event) error {
	for ctx.Err() == nil {
		f, err := os.Open(t.Path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			_ = f.Close()
			return err
		}
		err = t.tail(ctx, f, out)
		_ = f.Close()
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}

// LinesRead returns the running counter of records ingested.
func (t *EveTailer) LinesRead() uint64 { return t.lines.Load() }

// Dropped returns the count of records that failed to deliver to out.
func (t *EveTailer) Dropped() uint64 { return t.dropped.Load() }

func (t *EveTailer) tail(ctx context.Context, f *os.File, out chan<- model.Event) error {
	r := bufio.NewReader(f)
	for ctx.Err() == nil {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}
		if err != nil {
			return err
		}
		t.lines.Add(1)
		var rec EveRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		ev, ok := projectEve(rec)
		if !ok {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		default:
			t.dropped.Add(1)
		}
	}
	return nil
}

func projectEve(rec EveRecord) (model.Event, bool) {
	ev := model.NewEvent("netids.suricata", model.SeverityNotice)
	ev.Tags["event_type"] = rec.EventType
	ev.Tags["src_ip"] = rec.SrcIP
	ev.Tags["dst_ip"] = rec.DestIP
	ev.Tags["proto"] = rec.Proto
	switch rec.EventType {
	case "alert":
		if rec.Alert == nil {
			return ev, false
		}
		ev.Severity = severityFromSuricata(rec.Alert.Severity)
		ev.Tags["sig_id"] = itoa(rec.Alert.SignatureID)
		ev.Tags["signature"] = rec.Alert.Signature
		ev.Tags["category"] = rec.Alert.Category
		return ev, true
	case "dns":
		if rec.DNS == nil {
			return ev, false
		}
		ev.Tags["dns_qname"] = rec.DNS.Rrname
		ev.Tags["dns_rcode"] = rec.DNS.Rcode
		ev.Tags["dns_type"] = rec.DNS.QueryType
		return ev, true
	case "tls":
		if rec.TLS == nil {
			return ev, false
		}
		ev.Tags["sni"] = rec.TLS.SNI
		ev.Tags["ja3"] = rec.TLS.JA3.Hash
		ev.Tags["ja4"] = rec.TLS.JA4
		return ev, true
	case "flow", "http", "ssh", "fileinfo":
		return ev, true
	}
	return ev, false
}

func severityFromSuricata(n int) model.Severity {
	switch n {
	case 1:
		return model.SeverityCritical
	case 2:
		return model.SeverityHigh
	case 3:
		return model.SeverityWarn
	}
	return model.SeverityNotice
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
