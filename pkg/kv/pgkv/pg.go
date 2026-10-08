// Package pgkv implements kv.Store on PostgreSQL for multi-instance
// (serverless) deployments. Writers from every instance serialize on one
// transaction-scoped advisory lock, so relay invariants (sequence uniqueness,
// budgets, ledger order) hold globally. Within an instance, concurrent Updates
// are group-committed: one round trip opens the transaction and takes the
// lock, and one round trip writes all coalesced rows and commits.
package pgkv

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/21J3phy/silk/pkg/kv"
)

const (
	schema  = `CREATE TABLE IF NOT EXISTS silk_kv (k bytea PRIMARY KEY, v bytea NOT NULL)`
	lockKey = 0x5117 // advisory lock id shared by all relay instances
	channel = "silk_events"
)

// Options configures the store.
type Options struct {
	MaxConns int32 // pool size per instance (default 4)
	MaxBatch int   // Updates per commit (default 256)
}

// Store is a PostgreSQL-backed kv.Store.
type Store struct {
	dsn      string
	pool     *pgxpool.Pool
	reqs     chan *request
	stop     chan struct{}
	wg       sync.WaitGroup
	closed   atomic.Bool
	maxBatch int

	Batches atomic.Int64
	Updates atomic.Int64
	Rows    atomic.Int64
	// RoundTrips counts database round trips made by writes and reads.
	RoundTrips atomic.Int64
	// DBNanos is wall time spent waiting on the database (including pool waits).
	DBNanos atomic.Int64
}

// Timing reports cumulative round trips and database wait time.
func (s *Store) Timing() (int64, time.Duration) {
	return s.RoundTrips.Load(), time.Duration(s.DBNanos.Load())
}

func (s *Store) since(t0 time.Time) { s.DBNanos.Add(int64(time.Since(t0))) }

type request struct {
	ctx context.Context
	fn  func(kv.Tx) error
	err chan error
}

// Open connects, creates the table if needed, and starts the writer.
func Open(ctx context.Context, dsn string, o Options) (*Store, error) {
	if o.MaxConns <= 0 {
		o.MaxConns = 4
	}
	if o.MaxBatch <= 0 {
		o.MaxBatch = 256
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	cfg.MaxConns = o.MaxConns
	cfg.MaxConnIdleTime = 2 * time.Minute
	rp := cfg.ConnConfig.RuntimeParams
	rp["statement_timeout"] = "15000"
	rp["idle_in_transaction_session_timeout"] = "15000"
	rp["application_name"] = "silk-relay"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	s := &Store{dsn: dsn, pool: pool, reqs: make(chan *request, 1024), stop: make(chan struct{}), maxBatch: o.MaxBatch}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *Store) Update(ctx context.Context, fn func(kv.Tx) error) error {
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
	return <-req.err
}

func (s *Store) writer() {
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

func (s *Store) commit(batch []*request) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fail := func(err error) {
		for _, r := range batch {
			r.err <- err
		}
	}
	t0 := time.Now()
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		fail(err)
		return
	}
	defer conn.Release()
	// One round trip: open the transaction and take the global writer lock.
	b := &pgx.Batch{}
	b.Queue("BEGIN")
	b.Queue("SELECT pg_advisory_xact_lock($1)", int64(lockKey))
	s.RoundTrips.Add(1)
	err = conn.SendBatch(ctx, b).Close()
	s.since(t0)
	if err != nil {
		conn.Conn().Close(ctx)
		fail(err)
		return
	}
	rollback := func() { conn.Exec(context.Background(), "ROLLBACK") }
	base := &pgTx{ctx: ctx, q: conn, rt: &s.RoundTrips, ns: &s.DBNanos}
	ov := kv.NewOverlay(base)
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
		if base.err != nil { // a storage error poisons the transaction
			rollback()
			fail(base.err)
			return
		}
	}
	if kept == 0 {
		rollback()
		for i, r := range batch {
			r.err <- results[i]
		}
		return
	}
	var putK, putV, delK [][]byte
	ov.Writes(func(k, v []byte, deleted bool) error {
		if deleted {
			delK = append(delK, k)
		} else {
			putK, putV = append(putK, k), append(putV, v)
		}
		return nil
	})
	// One round trip: write every coalesced row and commit.
	wb := &pgx.Batch{}
	if len(putK) > 0 {
		wb.Queue(`INSERT INTO silk_kv (k, v) SELECT * FROM unnest($1::bytea[], $2::bytea[]) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`, putK, putV)
	}
	if len(delK) > 0 {
		wb.Queue(`DELETE FROM silk_kv WHERE k = ANY($1::bytea[])`, delK)
	}
	for _, t := range ov.Topics() {
		wb.Queue("SELECT pg_notify($1, $2)", channel, t) // delivered only if the commit succeeds
	}
	wb.Queue("COMMIT")
	s.RoundTrips.Add(1)
	t1 := time.Now()
	err = conn.SendBatch(ctx, wb).Close()
	s.since(t1)
	if err != nil {
		rollback()
		fail(err)
		return
	}
	s.Batches.Add(1)
	s.Updates.Add(int64(kept))
	s.Rows.Add(int64(len(putK) + len(delK)))
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

// View runs reads directly on the pool. Relay reads either touch one key/range
// or read immutable data (ledger hashes) after a size, so they do not need a
// snapshot transaction; skipping it saves two round trips per read.
func (s *Store) View(ctx context.Context, fn func(kv.Tx) error) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}
	t := &pgTx{ctx: ctx, q: s.pool, readOnly: true, rt: &s.RoundTrips, ns: &s.DBNanos}
	if err := safeRun(fn, t); err != nil {
		return err
	}
	return t.err
}

func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.stop)
	s.wg.Wait()
	s.pool.Close()
	return nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type pgTx struct {
	ctx      context.Context
	q        querier
	readOnly bool
	err      error
	rt       *atomic.Int64
	ns       *atomic.Int64
}

// trip counts a round trip; call the returned func when it completes.
func (t *pgTx) trip() func() {
	if t.rt != nil {
		t.rt.Add(1)
	}
	t0 := time.Now()
	return func() {
		if t.ns != nil {
			t.ns.Add(int64(time.Since(t0)))
		}
	}
}

func (t *pgTx) fail(err error) error {
	if t.err == nil {
		t.err = err
	}
	return err
}

func (t *pgTx) Get(key []byte) ([]byte, error) {
	var v []byte
	done := t.trip()
	err := t.q.QueryRow(t.ctx, "SELECT v FROM silk_kv WHERE k = $1", key).Scan(&v)
	done()
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, t.fail(err)
	}
	if v == nil {
		v = []byte{}
	}
	return v, nil
}

func (t *pgTx) GetMany(keys [][]byte) ([][]byte, error) {
	out := make([][]byte, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	pos := make(map[string][]int, len(keys))
	for i, k := range keys {
		pos[string(k)] = append(pos[string(k)], i)
	}
	done := t.trip()
	defer done()
	rows, err := t.q.Query(t.ctx, "SELECT k, v FROM silk_kv WHERE k = ANY($1::bytea[])", keys)
	if err != nil {
		return nil, t.fail(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, t.fail(err)
		}
		if v == nil {
			v = []byte{}
		}
		for _, i := range pos[string(k)] {
			out[i] = v
		}
	}
	if err := rows.Err(); err != nil {
		return nil, t.fail(err)
	}
	return out, nil
}

func (t *pgTx) Put(key, val []byte) error {
	return errors.New("pgkv: writes go through the overlay")
}

func (t *pgTx) Delete(key []byte) error {
	return errors.New("pgkv: writes go through the overlay")
}

func (t *pgTx) Scan(start, end []byte, limit int, fn func(k, v []byte) bool) error {
	var rows pgx.Rows
	var err error
	done := t.trip()
	lim := any(nil)
	if limit > 0 {
		lim = limit
	}
	if end == nil {
		rows, err = t.q.Query(t.ctx, "SELECT k, v FROM silk_kv WHERE k >= $1 ORDER BY k LIMIT $2", start, lim)
	} else {
		rows, err = t.q.Query(t.ctx, "SELECT k, v FROM silk_kv WHERE k >= $1 AND k < $2 ORDER BY k LIMIT $3", start, end, lim)
	}
	if err != nil {
		return t.fail(err)
	}
	// Buffer the rows before calling fn: in a write transaction the single
	// connection cannot run another query while a result set is open.
	type kvRow struct{ k, v []byte }
	var buf []kvRow
	for rows.Next() {
		var k, v []byte
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return t.fail(err)
		}
		if v == nil {
			v = []byte{}
		}
		buf = append(buf, kvRow{k, v})
	}
	rows.Close()
	done()
	if err := rows.Err(); err != nil {
		return t.fail(err)
	}
	for _, r := range buf {
		if !fn(r.k, r.v) {
			return nil
		}
	}
	return nil
}

// Watch LISTENs for topics published by any instance until ctx ends. Callers
// should only watch while someone is waiting: a held connection is cheap, but
// a scale-to-zero database cannot suspend while it is in use.
func (s *Store) Watch(ctx context.Context, fn func(topic string)) error {
	cfg, err := pgx.ParseConfig(s.dsn)
	if err != nil {
		return err
	}
	cfg.RuntimeParams["application_name"] = "silk-relay-listen"
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err == nil {
			if _, err = conn.Exec(ctx, "LISTEN "+channel); err == nil {
				backoff = 100 * time.Millisecond
				fn("") // (re)connected: waiters should re-check, they may have missed events
				for {
					n, err := conn.WaitForNotification(ctx)
					if err != nil {
						break
					}
					fn(n.Payload)
				}
			}
			conn.Close(context.Background())
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
	return ctx.Err()
}
