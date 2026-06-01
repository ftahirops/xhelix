package egressledger

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/zstd"
)

// parquetRow is the on-disk row schema. parquet-go infers the schema from
// struct tags.
type parquetRow struct {
	BucketUnixNano int64  `parquet:"bucket_ns"`
	Binary         string `parquet:"binary,zstd"`
	ExeSHA         string `parquet:"exe_sha,zstd"`
	UID            uint32 `parquet:"uid"`
	CGroupID       uint64 `parquet:"cgroup_id"`
	DestCIDR       string `parquet:"dest_cidr,zstd"`
	DestPort       uint32 `parquet:"dest_port"`
	Protocol       string `parquet:"protocol,zstd"`
	SNI            string `parquet:"sni,zstd"`
	DNSName        string `parquet:"dns_name,zstd"`
	DestClass      string `parquet:"dest_class,zstd"`
	ServiceRole    string `parquet:"service_role,zstd"`
	ParentComm     string `parquet:"parent_comm,zstd"`
	FirstSeenNS    int64  `parquet:"first_seen_ns"`
	LastSeenNS     int64  `parquet:"last_seen_ns"`
	Connects       uint64 `parquet:"connects"`
	BytesOut       uint64 `parquet:"bytes_out"`
	BytesIn        uint64 `parquet:"bytes_in"`
	DistinctDsts   uint32 `parquet:"distinct_dsts"`
	DenyEvents     uint64 `parquet:"deny_events"`
	VerifyEvents   uint64 `parquet:"verify_events"`
}

func recordToRow(r FlowRecord) parquetRow {
	return parquetRow{
		BucketUnixNano: r.Bucket.UnixNano(),
		Binary:         r.Key.Binary,
		ExeSHA:         r.Key.ExeSHA,
		UID:            r.Key.UID,
		CGroupID:       r.Key.CGroupID,
		DestCIDR:       r.Key.DestCIDR,
		DestPort:       uint32(r.Key.DestPort),
		Protocol:       r.Key.Protocol,
		SNI:            r.Key.SNI,
		DNSName:        r.Key.DNSName,
		DestClass:      r.Key.DestClass,
		ServiceRole:    r.Metrics.ServiceRole,
		ParentComm:     r.Metrics.ParentComm,
		FirstSeenNS:    r.Metrics.FirstSeen.UnixNano(),
		LastSeenNS:     r.Metrics.LastSeen.UnixNano(),
		Connects:       r.Metrics.Connects,
		BytesOut:       r.Metrics.BytesOut,
		BytesIn:        r.Metrics.BytesIn,
		DistinctDsts:   r.Metrics.DistinctDsts,
		DenyEvents:     r.Metrics.DenyEvents,
		VerifyEvents:   r.Metrics.VerifyEvents,
	}
}

func rowToRecord(p parquetRow) FlowRecord {
	return FlowRecord{
		Key: FlowKey{
			Binary:    p.Binary,
			ExeSHA:    p.ExeSHA,
			UID:       p.UID,
			CGroupID:  p.CGroupID,
			DestCIDR:  p.DestCIDR,
			DestPort:  uint16(p.DestPort),
			Protocol:  p.Protocol,
			SNI:       p.SNI,
			DNSName:   p.DNSName,
			DestClass: p.DestClass,
		},
		Metrics: FlowMetrics{
			FirstSeen:    time.Unix(0, p.FirstSeenNS),
			LastSeen:     time.Unix(0, p.LastSeenNS),
			Connects:     p.Connects,
			BytesOut:     p.BytesOut,
			BytesIn:      p.BytesIn,
			DistinctDsts: p.DistinctDsts,
			DenyEvents:   p.DenyEvents,
			VerifyEvents: p.VerifyEvents,
			ServiceRole:  p.ServiceRole,
			ParentComm:   p.ParentComm,
		},
		Bucket: time.Unix(0, p.BucketUnixNano),
	}
}

// coldStore manages per-day parquet files under <root>/parquet/YYYY-MM-DD/events.parquet.
type coldStore struct {
	mu   sync.Mutex
	root string
}

func newColdStore(root string) (*coldStore, error) {
	dir := filepath.Join(root, "parquet")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &coldStore{root: dir}, nil
}

// dayDir returns the dir path for a given UTC date.
func (c *coldStore) dayDir(t time.Time) string {
	return filepath.Join(c.root, t.UTC().Format("2006-01-02"))
}

func (c *coldStore) dayFile(t time.Time) string {
	return filepath.Join(c.dayDir(t), "events.parquet")
}

// appendRecords groups records by UTC day and appends them by rewriting the
// daily parquet file (read existing rows, merge with new rows, write back).
// This is simple and correct; throughput is acceptable because cold writes
// happen at most hourly with bounded record counts.
func (c *coldStore) appendRecords(recs []FlowRecord) error {
	if c == nil || len(recs) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	byDay := make(map[string][]FlowRecord)
	for _, r := range recs {
		day := r.Bucket.UTC().Format("2006-01-02")
		byDay[day] = append(byDay[day], r)
	}
	for day, drecs := range byDay {
		dir := filepath.Join(c.root, day)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		path := filepath.Join(dir, "events.parquet")
		existing, err := readParquet(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		rows := make([]parquetRow, 0, len(existing)+len(drecs))
		rows = append(rows, existing...)
		for _, r := range drecs {
			rows = append(rows, recordToRow(r))
		}
		if err := writeParquet(path, rows); err != nil {
			return err
		}
	}
	return nil
}

// readParquet reads all rows from path. Returns os.ErrNotExist if missing.
func readParquet(path string) ([]parquetRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() == 0 {
		return nil, nil
	}
	pf, err := parquet.OpenFile(f, st.Size())
	if err != nil {
		return nil, err
	}
	reader := parquet.NewGenericReader[parquetRow](pf)
	defer reader.Close()
	var out []parquetRow
	buf := make([]parquetRow, 256)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// writeParquet writes rows to path atomically (write to .tmp then rename).
func writeParquet(path string, rows []parquetRow) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := parquet.NewGenericWriter[parquetRow](f, parquet.Compression(&zstd.Codec{}))
	if _, err := w.Write(rows); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := w.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// scan walks rows across all per-day files whose date overlaps [start, end].
func (c *coldStore) scan(start, end time.Time, fn func(FlowRecord) bool) error {
	if c == nil {
		return nil
	}
	// iterate from start day to end day in UTC
	startDay := time.Date(start.UTC().Year(), start.UTC().Month(), start.UTC().Day(), 0, 0, 0, 0, time.UTC)
	endDay := time.Date(end.UTC().Year(), end.UTC().Month(), end.UTC().Day(), 0, 0, 0, 0, time.UTC)
	for d := startDay; !d.After(endDay); d = d.Add(24 * time.Hour) {
		path := filepath.Join(c.root, d.Format("2006-01-02"), "events.parquet")
		rows, err := readParquet(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, p := range rows {
			r := rowToRecord(p)
			if r.Bucket.Before(start) || r.Bucket.After(end) {
				continue
			}
			if !fn(r) {
				return nil
			}
		}
	}
	return nil
}

// pruneOlderThan removes daily parquet dirs whose date is strictly before
// the cutoff day (UTC).
func (c *coldStore) pruneOlderThan(cutoff time.Time) error {
	if c == nil {
		return nil
	}
	cutDay := time.Date(cutoff.UTC().Year(), cutoff.UTC().Month(), cutoff.UTC().Day(), 0, 0, 0, 0, time.UTC)
	entries, err := os.ReadDir(c.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d, err := time.ParseInLocation("2006-01-02", e.Name(), time.UTC)
		if err != nil {
			continue
		}
		if d.Before(cutDay) {
			if err := os.RemoveAll(filepath.Join(c.root, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// dayCount returns the number of day directories present.
func (c *coldStore) dayCount() int {
	if c == nil {
		return 0
	}
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n
}

// totalBytes returns the sum of file sizes under root.
func (c *coldStore) totalBytes() int64 {
	if c == nil {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(c.root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

// daysSorted returns the day dirs sorted ascending.
func (c *coldStore) daysSorted() []string {
	if c == nil {
		return nil
	}
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, perr := time.Parse("2006-01-02", e.Name()); perr != nil {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

