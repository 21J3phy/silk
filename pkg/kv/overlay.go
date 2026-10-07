package kv

import (
	"bytes"
	"sort"
)

// Base is the minimal read/write interface a backend transaction provides.
// Overlay builds the full Tx semantics (isolation of individual updates inside
// a group commit, read-your-writes, write coalescing) on top of it.
type Base interface {
	Get(key []byte) ([]byte, error)
	GetMany(keys [][]byte) ([][]byte, error)
	Scan(start, end []byte, limit int, fn func(k, v []byte) bool) error
}

type entry struct {
	val     []byte
	deleted bool
}

// Overlay buffers writes in memory. Updates in a group commit each run as
// an isolated layer: writes go straight into the batch map and an undo log
// records what they replaced, so a failed update is rolled back exactly and a
// successful one costs nothing extra to keep. The batch is written to the
// backend once at commit, so N updates touching the same key cost one row write.
type Overlay struct {
	base   Base
	batch  map[string]entry
	undo   []undoRec
	active bool
	keys   []string
	// cache holds values read from the backend during this batch. It is valid
	// because the batch holds the store's writer lock: nothing else can change
	// those rows until commit. Writes (batch) always shadow it.
	cache map[string][]byte
	// topics published by kept updates; opTopics belong to the current update.
	topics, opTopics []string
}

type undoRec struct {
	key     string
	prev    entry
	existed bool
}

// NewOverlay wraps a backend transaction.
func NewOverlay(base Base) *Overlay {
	return &Overlay{base: base, batch: make(map[string]entry, 256)}
}

// Reset reuses the overlay (and its allocated map) for a new backend transaction.
func (o *Overlay) Reset(base Base) {
	o.base = base
	clear(o.batch)
	clear(o.cache)
	o.undo, o.active = o.undo[:0], false
	o.keys = o.keys[:0]
	o.topics, o.opTopics = o.topics[:0], o.opTopics[:0]
}

// Begin starts an isolated update layer.
func (o *Overlay) Begin() { o.undo, o.active, o.opTopics = o.undo[:0], true, o.opTopics[:0] }

// Keep accepts the current update layer.
func (o *Overlay) Keep() {
	o.undo, o.active = o.undo[:0], false
	o.topics = append(o.topics, o.opTopics...)
	o.opTopics = o.opTopics[:0]
}

// Notify records a topic to publish if the current update is kept.
func (o *Overlay) Notify(topic string) { o.opTopics = append(o.opTopics, topic) }

// Topics returns the distinct topics of kept updates.
func (o *Overlay) Topics() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range o.topics {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// Discard rolls back the current update layer.
func (o *Overlay) Discard() {
	for i := len(o.undo) - 1; i >= 0; i-- {
		u := o.undo[i]
		if u.existed {
			o.batch[u.key] = u.prev
		} else {
			delete(o.batch, u.key)
		}
	}
	o.undo, o.active = o.undo[:0], false
	o.opTopics = o.opTopics[:0]
}

// Writes returns the coalesced batch writes in key order.
func (o *Overlay) Writes(fn func(key, val []byte, deleted bool) error) error {
	keys := o.keys[:0]
	for k := range o.batch {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	o.keys = keys
	for _, k := range keys {
		e := o.batch[k]
		if err := fn([]byte(k), e.val, e.deleted); err != nil {
			return err
		}
	}
	return nil
}

// Len is the number of coalesced writes pending.
func (o *Overlay) Len() int { return len(o.batch) }

func (o *Overlay) lookup(k string) (entry, bool) {
	e, ok := o.batch[k]
	return e, ok
}

func (o *Overlay) set(k string, e entry) {
	prev, existed := o.batch[k]
	o.undo = append(o.undo, undoRec{key: k, prev: prev, existed: existed})
	o.batch[k] = e
}

func (o *Overlay) Get(key []byte) ([]byte, error) {
	if e, ok := o.lookup(string(key)); ok {
		if e.deleted {
			return nil, nil
		}
		return e.val, nil
	}
	if v, ok := o.cache[string(key)]; ok {
		return v, nil
	}
	v, err := o.base.Get(key)
	if err == nil {
		o.remember(string(key), v)
	}
	return v, err
}

func (o *Overlay) remember(k string, v []byte) {
	if o.cache == nil {
		o.cache = make(map[string][]byte, 256)
	}
	o.cache[k] = v
}

// Prefetch reads keys from the backend in one round trip so that later Gets
// in this batch are served from memory. Implements kv.Prefetcher.
func (o *Overlay) Prefetch(keys [][]byte) error {
	var miss [][]byte
	for _, k := range keys {
		if _, ok := o.lookup(string(k)); ok {
			continue
		}
		if _, ok := o.cache[string(k)]; ok {
			continue
		}
		miss = append(miss, k)
	}
	if len(miss) == 0 {
		return nil
	}
	vals, err := o.base.GetMany(miss)
	if err != nil {
		return err
	}
	for i, k := range miss {
		o.remember(string(k), vals[i])
	}
	return nil
}

func (o *Overlay) GetMany(keys [][]byte) ([][]byte, error) {
	out := make([][]byte, len(keys))
	var miss [][]byte
	var missIdx []int
	for i, k := range keys {
		if e, ok := o.lookup(string(k)); ok {
			if !e.deleted {
				out[i] = e.val
			}
			continue
		}
		if v, ok := o.cache[string(k)]; ok {
			out[i] = v
			continue
		}
		miss = append(miss, k)
		missIdx = append(missIdx, i)
	}
	if len(miss) > 0 {
		vals, err := o.base.GetMany(miss)
		if err != nil {
			return nil, err
		}
		for j, v := range vals {
			out[missIdx[j]] = v
			o.remember(string(miss[j]), v)
		}
	}
	return out, nil
}

func (o *Overlay) Put(key, val []byte) error {
	cp := make([]byte, len(val)) // never nil: an empty value is present, not deleted
	copy(cp, val)
	o.set(string(key), entry{val: cp})
	return nil
}

func (o *Overlay) Delete(key []byte) error {
	o.set(string(key), entry{deleted: true})
	return nil
}

func inRange(k, start, end []byte) bool {
	return bytes.Compare(k, start) >= 0 && (end == nil || bytes.Compare(k, end) < 0)
}

// Scan merges backend rows with buffered writes in key order.
func (o *Overlay) Scan(start, end []byte, limit int, fn func(k, v []byte) bool) error {
	// Buffered keys in range (op layer shadows batch layer).
	merged := map[string]entry{}
	for k, e := range o.batch {
		if inRange([]byte(k), start, end) {
			merged[k] = e
		}
	}
	if len(merged) == 0 {
		return o.base.Scan(start, end, limit, fn)
	}
	buf := make([]string, 0, len(merged))
	for k := range merged {
		buf = append(buf, k)
	}
	sort.Strings(buf)
	emitted := 0
	stopped := false
	bi := 0
	emit := func(k, v []byte) bool {
		if limit > 0 && emitted >= limit {
			stopped = true
			return false
		}
		emitted++
		if !fn(k, v) {
			stopped = true
			return false
		}
		return true
	}
	// flushBefore emits buffered keys strictly less than k (or all if k == nil).
	flushBefore := func(k []byte) bool {
		for bi < len(buf) && (k == nil || buf[bi] < string(k)) {
			e := merged[buf[bi]]
			bi++
			if !e.deleted && !emit([]byte(buf[bi-1]), e.val) {
				return false
			}
		}
		return true
	}
	// The backend limit must account for rows the overlay hides; scan without limit and stop via callback.
	err := o.base.Scan(start, end, 0, func(k, v []byte) bool {
		if !flushBefore(k) {
			return false
		}
		if bi < len(buf) && buf[bi] == string(k) {
			e := merged[buf[bi]]
			bi++
			if e.deleted {
				return true
			}
			return emit(k, e.val)
		}
		return emit(k, v)
	})
	if err != nil || stopped {
		return err
	}
	flushBefore(nil)
	return nil
}
