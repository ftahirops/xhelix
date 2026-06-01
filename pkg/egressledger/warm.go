package egressledger

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"hash/fnv"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	badgeropts "github.com/dgraph-io/badger/v4/options"
)

// warmStore wraps a badger DB used as the 5-minute bucket store.
type warmStore struct {
	db     *badger.DB
	bucket time.Duration
}

func newWarmStore(dir string, bucket time.Duration) (*warmStore, error) {
	opts := badger.DefaultOptions(dir).
		WithCompression(badgeropts.ZSTD).
		WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &warmStore{db: db, bucket: bucket}, nil
}

func (w *warmStore) close() error {
	if w == nil || w.db == nil {
		return nil
	}
	return w.db.Close()
}

// fnv8 returns an 8-byte FNV-1a hash of s.
func fnv8(s string) [8]byte {
	h := fnv.New64a()
	h.Write([]byte(s))
	v := h.Sum64()
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], v)
	return out
}

// encodeKey builds the warm key:
//   bucket_ts(8B BE) | cidr_hash(8B) | port(2B BE) | uid(4B BE) | binhash(8B) | snihash(8B) | dnshash(8B)
func encodeKey(bucket time.Time, k FlowKey) []byte {
	buf := make([]byte, 0, 8+8+2+4+8+8+8)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(bucket.UnixNano()))
	buf = append(buf, ts[:]...)
	ch := fnv8(k.DestCIDR + "|" + k.Protocol + "|" + k.DestClass)
	buf = append(buf, ch[:]...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], k.DestPort)
	buf = append(buf, p[:]...)
	var u [4]byte
	binary.BigEndian.PutUint32(u[:], k.UID)
	buf = append(buf, u[:]...)
	bh := fnv8(k.Binary + "|" + k.ExeSHA)
	buf = append(buf, bh[:]...)
	sh := fnv8(k.SNI)
	buf = append(buf, sh[:]...)
	dh := fnv8(k.DNSName)
	buf = append(buf, dh[:]...)
	return buf
}

// bucketFromKey returns the bucket timestamp portion of a warm key.
func bucketFromKey(key []byte) time.Time {
	if len(key) < 8 {
		return time.Time{}
	}
	ns := binary.BigEndian.Uint64(key[:8])
	return time.Unix(0, int64(ns))
}

// encodeValue gob-encodes a FlowRecord (Key + Metrics; bucket reconstructed
// from the key).
func encodeValue(r FlowRecord) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(&r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeValue(b []byte) (FlowRecord, error) {
	var r FlowRecord
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&r); err != nil {
		return r, err
	}
	return r, nil
}

// putRecords merges hot-evicted records into warm. We round each record's
// bucket up to the warm bucket granularity, then merge if a row exists.
func (w *warmStore) putRecords(recs []FlowRecord) error {
	if w == nil || w.db == nil || len(recs) == 0 {
		return nil
	}
	return w.db.Update(func(txn *badger.Txn) error {
		for _, r := range recs {
			b := r.Bucket.Truncate(w.bucket)
			key := encodeKey(b, r.Key)
			// merge with existing if any
			item, err := txn.Get(key)
			if err == nil {
				var prev FlowRecord
				if verr := item.Value(func(v []byte) error {
					pr, derr := decodeValue(v)
					if derr != nil {
						return derr
					}
					prev = pr
					return nil
				}); verr == nil {
					r = mergeRecord(prev, r)
				}
			} else if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
			r.Bucket = b
			val, err := encodeValue(r)
			if err != nil {
				return err
			}
			if err := txn.Set(key, val); err != nil {
				return err
			}
		}
		return nil
	})
}

// mergeRecord combines two records with the same key/bucket.
func mergeRecord(a, b FlowRecord) FlowRecord {
	out := a
	if b.Metrics.FirstSeen.Before(out.Metrics.FirstSeen) || out.Metrics.FirstSeen.IsZero() {
		out.Metrics.FirstSeen = b.Metrics.FirstSeen
	}
	if b.Metrics.LastSeen.After(out.Metrics.LastSeen) {
		out.Metrics.LastSeen = b.Metrics.LastSeen
	}
	out.Metrics.Connects += b.Metrics.Connects
	out.Metrics.BytesOut += b.Metrics.BytesOut
	out.Metrics.BytesIn += b.Metrics.BytesIn
	if b.Metrics.DistinctDsts > out.Metrics.DistinctDsts {
		out.Metrics.DistinctDsts = b.Metrics.DistinctDsts
	}
	out.Metrics.DenyEvents += b.Metrics.DenyEvents
	out.Metrics.VerifyEvents += b.Metrics.VerifyEvents
	// Descriptive enrichment: last-observed-non-empty wins (consistent with
	// the hot-ring merge). Without this, merging same-key records would drop
	// the newer record's service_role/parent_comm.
	if b.Metrics.ServiceRole != "" {
		out.Metrics.ServiceRole = b.Metrics.ServiceRole
	}
	if b.Metrics.ParentComm != "" {
		out.Metrics.ParentComm = b.Metrics.ParentComm
	}
	if b.Metrics.L7Protocol != "" {
		out.Metrics.L7Protocol = b.Metrics.L7Protocol
	}
	return out
}

// scan walks all records with bucket in [start, end].
func (w *warmStore) scan(start, end time.Time, fn func(FlowRecord) bool) error {
	if w == nil || w.db == nil {
		return nil
	}
	startNs := uint64(start.UnixNano())
	endNs := uint64(end.UnixNano())
	return w.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		var startKey [8]byte
		binary.BigEndian.PutUint64(startKey[:], startNs)
		for it.Seek(startKey[:]); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			if len(key) < 8 {
				continue
			}
			ts := binary.BigEndian.Uint64(key[:8])
			if ts > endNs {
				break
			}
			var rec FlowRecord
			if err := item.Value(func(v []byte) error {
				r, derr := decodeValue(v)
				if derr != nil {
					return derr
				}
				rec = r
				return nil
			}); err != nil {
				return err
			}
			if !fn(rec) {
				return nil
			}
		}
		return nil
	})
}

// pruneOlderThan deletes warm keys whose bucket ts is before cutoff.
func (w *warmStore) pruneOlderThan(cutoff time.Time) error {
	if w == nil || w.db == nil {
		return nil
	}
	cn := uint64(cutoff.UnixNano())
	return w.db.Update(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		var toDel [][]byte
		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().KeyCopy(nil)
			if len(key) < 8 {
				continue
			}
			ts := binary.BigEndian.Uint64(key[:8])
			if ts < cn {
				toDel = append(toDel, key)
			} else {
				break
			}
		}
		for _, k := range toDel {
			if err := txn.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// drainOlderThan returns and deletes all warm records with bucket ts < cutoff.
func (w *warmStore) drainOlderThan(cutoff time.Time) ([]FlowRecord, error) {
	if w == nil || w.db == nil {
		return nil, nil
	}
	cn := uint64(cutoff.UnixNano())
	var out []FlowRecord
	err := w.db.Update(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		var toDel [][]byte
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			if len(key) < 8 {
				continue
			}
			ts := binary.BigEndian.Uint64(key[:8])
			if ts >= cn {
				break
			}
			var rec FlowRecord
			if err := item.Value(func(v []byte) error {
				r, derr := decodeValue(v)
				if derr != nil {
					return derr
				}
				rec = r
				return nil
			}); err != nil {
				return err
			}
			out = append(out, rec)
			toDel = append(toDel, key)
		}
		for _, k := range toDel {
			if err := txn.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// keyCount returns the approximate number of keys.
func (w *warmStore) keyCount() int {
	if w == nil || w.db == nil {
		return 0
	}
	n := 0
	_ = w.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.IteratorOptions{PrefetchValues: false})
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			n++
		}
		return nil
	})
	return n
}
