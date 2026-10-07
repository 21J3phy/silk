// Package sqlitekv implements kv.Store on a single SQLite file using the
// pure-Go SQLite engine through zombiezen.com/go/sqlite's low-level API
// (connection-cached prepared statements, no database/sql layer).
package sqlitekv

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/21J3phy/silk/pkg/kv"
)

// SQLite is a single-file store. All writes flow through one goroutine and one
// connection that group-commits: while one batch is being made durable, new
// Updates queue and are committed together in the next batch with one fsync.
// Each Update runs in its own kv.Overlay layer, so a failing Update is rolled
// back in memory and repeated writes to a key are coalesced into one row write.
type SQLite struct {
	w        *sqlite.Conn
	readers  *sqlitex.Pool
	reqs     chan *request
	stop     chan struct{}
	wg       sync.WaitGroup
	closed   atomic.Bool
	maxBatch int
	ov       *kv.Overlay // reused by the writer goroutine

	Batches atomic.Int64
	Updates atomic.Int64
	Rows    atomic.Int64
}

type request struct {
	ctx context.Context
	fn  func(kv.Tx) error
	err chan error
}

// SQLiteOptions tunes durability and batching.
type SQLiteOptions struct {
	// Synchronous is the SQLite synchronous pragma: "FULL" (default, durable
	// against power loss) or "NORMAL" (durable against process crashes).
	Synchronous string
	// MaxBatch caps how many Updates share one commit (default 512; 1 disables grouping).
	MaxBatch int
	// Readers is the read connection pool size (default 4).
	Readers int
	// CacheMB is the writer's page cache (default 4). Larger caches trade
	// memory for throughput once the database outgrows the cache.
	CacheMB int
}

const schema = `CREATE TABLE IF NOT EXISTS kv (k BLOB PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID`

func pragmas(conn *sqlite.Conn, list ...string) error {
	for _, p := range list {
		if err := sqlitex.ExecuteTransient(conn, "PRAGMA "+p, nil); err != nil {
			return fmt.Errorf("PRAGMA %s: %w", p, err)
		}
	}
	return nil
}

// Open opens or creates a store at path.
func Open(path string, o SQLiteOptions) (*SQLite, error) {
	if o.Synchronous == "" {
		o.Synchronous = "FULL"
	}
	if o.Synchronous != "FULL" && o.Synchronous != "NORMAL" && o.Synchronous != "OFF" {
		return nil, fmt.Errorf("invalid synchronous mode %q", o.Synchronous)
	}
	if o.MaxBatch <= 0 {
		o.MaxBatch = 512
	}
	if o.Readers <= 0 {
		o.Readers = 4
	}
	if o.CacheMB <= 0 {
		o.CacheMB = 4
	}
	w, err := sqlite.OpenConn(path, sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenNoMutex)
	if err != nil {
		return nil, err
	}
	w.SetBusyTimeout(10 * time.Second)
	if err := pragmas(w, "journal_mode=WAL", "synchronous="+o.Synchronous, "temp_store=MEMORY", fmt.Sprintf("cache_size=-%d", o.CacheMB*1000)); err != nil {
		w.Close()
		return nil, err
	}
	if err := sqlitex.ExecuteTransient(w, schema, nil); err != nil {
		w.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	readers, err := sqlitex.NewPool(path, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadOnly | sqlite.OpenNoMutex,
		PoolSize: o.Readers,
		PrepareConn: func(c *sqlite.Conn) error {
			c.SetBusyTimeout(10 * time.Second)
			return pragmas(c, "query_only=1", "temp_store=MEMORY", "cache_size=-1000")
		},
	})
	if err != nil {
		w.Close()
		return nil, err
	}
	s := &SQLite{w: w, readers: readers, reqs: make(chan *request, 4096), stop: make(chan struct{}), maxBatch: o.MaxBatch}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *SQLite) Update(ctx context.Context, fn func(kv.Tx) error) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}
	req := &request{ctx: ctx, fn: fn, err: make(chan error, 1)}
	select {
	case s.reqs <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stop:
		return kv.ErrClosed
	}
	// Once queued, wait for the outcome even if ctx ends: the write may already be committed.
	return <-req.err
}

func (s *SQLite) writer() {
	defer s.wg.Done()
	batch := make([]*request, 0, s.maxBatch)
	for {
		var first *request
		select {
		case first = <-s.reqs:
		case <-s.stop:
			for {
				select {
				case r := <-s.reqs:
					r.err <- kv.ErrClosed
				default:
					return
				}
			}
		}
		batch = append(batch[:0], first)
	drain:
		for len(batch) < s.maxBatch {
			select {
			case r := <-s.reqs:
				batch = append(batch, r)
			default:
				break drain
			}
		}
		s.commit(batch)
	}
}

func (s *SQLite) commit(batch []*request) {
	fail := func(err error) {
		for _, r := range batch {
			r.err <- err
		}
	}
	if err := sqlitex.Execute(s.w, "BEGIN IMMEDIATE", nil); err != nil {
		fail(err)
		return
	}
	base := &connTx{conn: s.w}
	if s.ov == nil {
		s.ov = kv.NewOverlay(base)
	}
	ov := s.ov
	ov.Reset(base)
	results := make([]error, len(batch))
	kept := 0
	for i, r := range batch {
		if err := r.ctx.Err(); err != nil {
			results[i] = err
			continue
		}
		ov.Begin()
		if results[i] = safeRun(r.fn, ov); results[i] != nil {
			ov.Discard()
		} else {
			ov.Keep()
			kept++
		}
	}
	rows := 0
	var err error
	if kept > 0 {
		err = ov.Writes(func(k, v []byte, deleted bool) error {
			rows++
			if deleted {
				return base.del(k)
			}
			return base.put(k, v)
		})
	}
	if err == nil && kept > 0 {
		err = sqlitex.Execute(s.w, "COMMIT", nil)
	}
	if err != nil || kept == 0 {
		if rerr := sqlitex.Execute(s.w, "ROLLBACK", nil); rerr != nil && err == nil {
			err = rerr
		}
	}
	if err != nil {
		fail(err)
		return
	}
	if kept > 0 {
		s.Batches.Add(1)
		s.Updates.Add(int64(kept))
		s.Rows.Add(int64(rows))
	}
	for i, r := range batch {
		r.err <- results[i]
	}
}

func safeRun(fn func(kv.Tx) error, t kv.Tx) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("transaction panic: %v", p)
		}
	}()
	return fn(t)
}

// View runs fn in a read snapshot on a pooled read-only connection.
func (s *SQLite) View(ctx context.Context, fn func(kv.Tx) error) (err error) {
	if s.closed.Load() {
		return kv.ErrClosed
	}
	conn, err := s.readers.Take(ctx)
	if err != nil {
		return err
	}
	defer s.readers.Put(conn)
	if err := sqlitex.Execute(conn, "BEGIN", nil); err != nil {
		return err
	}
	defer func() {
		if rerr := sqlitex.Execute(conn, "ROLLBACK", nil); rerr != nil && err == nil {
			err = rerr
		}
	}()
	return safeRun(fn, &connTx{conn: conn, readOnly: true})
}

func (s *SQLite) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.stop)
	s.wg.Wait()
	return errors.Join(s.readers.Close(), s.w.Close())
}

// connTx implements kv.Base (and kv.Tx for reads) on one connection.
type connTx struct {
	conn     *sqlite.Conn
	readOnly bool
}

func column(stmt *sqlite.Stmt, col int) []byte {
	b := make([]byte, stmt.ColumnLen(col)) // never nil: empty BLOBs are present values
	stmt.ColumnBytes(col, b)
	return b
}

func (t *connTx) Get(key []byte) ([]byte, error) {
	stmt := t.conn.Prep("SELECT v FROM kv WHERE k = ?1")
	defer stmt.Reset()
	stmt.BindBytes(1, key)
	ok, err := stmt.Step()
	if err != nil || !ok {
		return nil, err
	}
	return column(stmt, 0), nil
}

const maxMany = 64

var manyQueries = func() []string {
	q := make([]string, maxMany+1)
	for n := 2; n <= maxMany; n++ {
		var b strings.Builder
		b.WriteString("SELECT k, v FROM kv WHERE k IN (?1")
		for i := 2; i <= n; i++ {
			b.WriteString(",?" + strconv.Itoa(i))
		}
		b.WriteString(")")
		q[n] = b.String()
	}
	return q
}()

func (t *connTx) GetMany(keys [][]byte) ([][]byte, error) {
	out := make([][]byte, len(keys))
	for start := 0; start < len(keys); start += maxMany {
		end := min(start+maxMany, len(keys))
		if err := t.getChunk(keys[start:end], out[start:end]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (t *connTx) getChunk(keys [][]byte, out [][]byte) error {
	pos := make(map[string][]int, len(keys))
	uniq := make([][]byte, 0, len(keys))
	for i, k := range keys {
		s := string(k)
		if _, dup := pos[s]; !dup {
			uniq = append(uniq, k)
		}
		pos[s] = append(pos[s], i)
	}
	if len(uniq) == 1 {
		v, err := t.Get(uniq[0])
		for i := range out {
			out[i] = v
		}
		return err
	}
	stmt := t.conn.Prep(manyQueries[len(uniq)])
	defer stmt.Reset()
	for i, k := range uniq {
		stmt.BindBytes(i+1, k)
	}
	for {
		ok, err := stmt.Step()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		k := column(stmt, 0)
		v := column(stmt, 1)
		for _, i := range pos[string(k)] {
			out[i] = v
		}
	}
}

func (t *connTx) put(key, val []byte) error {
	stmt := t.conn.Prep("INSERT INTO kv (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v")
	defer stmt.Reset()
	stmt.BindBytes(1, key)
	if len(val) == 0 {
		stmt.BindZeroBlob(2, 0)
	} else {
		stmt.BindBytes(2, val)
	}
	_, err := stmt.Step()
	return err
}

func (t *connTx) del(key []byte) error {
	stmt := t.conn.Prep("DELETE FROM kv WHERE k = ?1")
	defer stmt.Reset()
	stmt.BindBytes(1, key)
	_, err := stmt.Step()
	return err
}

func (t *connTx) Put(key, val []byte) error {
	if t.readOnly {
		return errors.New("write in read-only transaction")
	}
	return t.put(key, val)
}

func (t *connTx) Delete(key []byte) error {
	if t.readOnly {
		return errors.New("write in read-only transaction")
	}
	return t.del(key)
}

func (t *connTx) Scan(start, end []byte, limit int, fn func(k, v []byte) bool) error {
	if limit <= 0 {
		limit = -1
	}
	var stmt *sqlite.Stmt
	if end == nil {
		stmt = t.conn.Prep("SELECT k, v FROM kv WHERE k >= ?1 ORDER BY k LIMIT ?2")
		stmt.BindBytes(1, start)
		stmt.BindInt64(2, int64(limit))
	} else {
		stmt = t.conn.Prep("SELECT k, v FROM kv WHERE k >= ?1 AND k < ?2 ORDER BY k LIMIT ?3")
		stmt.BindBytes(1, start)
		stmt.BindBytes(2, end)
		stmt.BindInt64(3, int64(limit))
	}
	defer stmt.Reset()
	for {
		ok, err := stmt.Step()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if !fn(column(stmt, 0), column(stmt, 1)) {
			return nil
		}
	}
}
