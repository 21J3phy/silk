package relay

import (
	"encoding/binary"
	"errors"

	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/wire"
)

// Buckets. Ledger uses 'L', 'H', and 'S' (see package ledger).
const (
	bAgent       = 'A' // agentID -> agentRec
	bAgentHist   = 'a' // agentID||serial -> cert frame (superseded certs)
	bAgentKey    = 'k' // agentID -> agentKey (compact hot-path view of the current cert)
	bHandle      = 'N' // handle -> agentID
	bIntro       = 'I' // introID -> introRec
	bPairPending = 'p' // from||to -> introID while pending
	bGrant       = 'G' // grantID -> grantRec
	bGrantCtr    = 'g' // grantID -> grantCtr
	bSeq         = 'Q' // grantID||dir||seq -> msgID
	bMsg         = 'M' // msgID -> msgRec
	bGrantOpen   = 'W' // grantID||msgID -> (pending messages of a grant)
	bEvent       = 'E' // agentID||evseq -> event
	bEventSeq    = 'e' // agentID -> next evseq
	bExpiry      = 'X' // expiresMs||kind||id -> nil
	bRecipient   = 'P' // agentID -> recipient pressure
	bReputation  = 'R' // agentID -> sender reputation
	bOutstanding = 'O' // agentID -> pending intros sent
	bFind        = 'F' // sha256(frame) -> ledger index
	bPolicy      = 'Y' // agentID -> owner-signed contact policy frame
	bQueue       = 'q' // recipient||bits||created||introID -> nil (stranger queue, cheapest first)
	bTrustedPend = 't' // recipient -> pending trusted intros (u32)
	bStat        = 's' // name -> u64
)

const (
	statusActive   = 1
	statusRevoked  = 2
	statusPending  = 1
	statusAccepted = 2
	statusDeclined = 3
	statusExpired  = 4
	statusEvicted  = 5 // outbid while pending in a full stranger queue
	statusAcked    = 2
	statusPurged   = 3 // message removed because its grant was revoked
)

var errCorrupt = errors.New("relay: corrupt record")

type enc struct{ b []byte }

func (e *enc) u8(v uint8)   { e.b = append(e.b, v) }
func (e *enc) u16(v uint16) { e.b = binary.BigEndian.AppendUint16(e.b, v) }
func (e *enc) u32(v uint32) { e.b = binary.BigEndian.AppendUint32(e.b, v) }
func (e *enc) u64(v uint64) { e.b = binary.BigEndian.AppendUint64(e.b, v) }
func (e *enc) i64(v int64)  { e.u64(uint64(v)) }
func (e *enc) id(v wire.ID) { e.b = append(e.b, v[:]...) }
func (e *enc) raw(p []byte) { e.b = append(e.b, p...) }

type dec struct {
	b   []byte
	bad bool
}

func (d *dec) take(n int) []byte {
	if d.bad || len(d.b) < n {
		d.bad = true
		return make([]byte, n)
	}
	p := d.b[:n]
	d.b = d.b[n:]
	return p
}
func (d *dec) u8() uint8   { return d.take(1)[0] }
func (d *dec) u16() uint16 { return binary.BigEndian.Uint16(d.take(2)) }
func (d *dec) u32() uint32 { return binary.BigEndian.Uint32(d.take(4)) }
func (d *dec) u64() uint64 { return binary.BigEndian.Uint64(d.take(8)) }
func (d *dec) i64() int64  { return int64(d.u64()) }
func (d *dec) id() (v wire.ID) {
	copy(v[:], d.take(wire.IDLen))
	return
}
func (d *dec) rest() []byte {
	p := d.b
	d.b = nil
	return p
}

// agentRec: status | registeredMs | ledgerIdx | cert frame
type agentRec struct {
	Status     uint8
	Registered int64
	LedgerIdx  int64
	Cert       *wire.Cert
}

func (r *agentRec) encode() []byte {
	e := enc{b: make([]byte, 0, 17+len(r.Cert.Raw))}
	e.u8(r.Status)
	e.i64(r.Registered)
	e.i64(r.LedgerIdx)
	e.raw(r.Cert.Raw)
	return e.b
}

func decodeAgent(v []byte) (*agentRec, error) {
	d := dec{b: v}
	r := &agentRec{Status: d.u8(), Registered: d.i64(), LedgerIdx: d.i64()}
	if d.bad {
		return nil, errCorrupt
	}
	c, err := wire.DecodeCert(append([]byte{}, d.rest()...))
	if err != nil {
		return nil, errCorrupt
	}
	r.Cert = c
	return r, nil
}

// introRec: status | trusted | ledgerIdx | frame
type introRec struct {
	Status    uint8
	Trusted   bool
	LedgerIdx int64
	Intro     *wire.Intro
}

func (r *introRec) encode() []byte {
	e := enc{b: make([]byte, 0, 10+len(r.Intro.Raw))}
	e.u8(r.Status)
	if r.Trusted {
		e.u8(1)
	} else {
		e.u8(0)
	}
	e.i64(r.LedgerIdx)
	e.raw(r.Intro.Raw)
	return e.b
}

func decodeIntro(v []byte) (*introRec, error) {
	d := dec{b: v}
	r := &introRec{Status: d.u8(), Trusted: d.u8() == 1, LedgerIdx: d.i64()}
	if d.bad {
		return nil, errCorrupt
	}
	in, err := wire.DecodeIntro(append([]byte{}, d.rest()...))
	if err != nil {
		return nil, errCorrupt
	}
	r.Intro = in
	return r, nil
}

func queueKey(in *wire.Intro) []byte {
	return kv.Key(bQueue, in.To[:], []byte{in.PoWBits}, kv.U64(uint64(in.Created)), in.IntroID[:])
}

// grantRec: status | ledgerIdx | frame
type grantRec struct {
	Status    uint8
	LedgerIdx int64
	Grant     *wire.Grant
}

func (r *grantRec) encode() []byte {
	e := enc{b: make([]byte, 0, 9+len(r.Grant.Raw))}
	e.u8(r.Status)
	e.i64(r.LedgerIdx)
	e.raw(r.Grant.Raw)
	return e.b
}

func decodeGrant(v []byte) (*grantRec, error) {
	d := dec{b: v}
	r := &grantRec{Status: d.u8(), LedgerIdx: d.i64()}
	if d.bad {
		return nil, errCorrupt
	}
	g, err := wire.DecodeGrant(append([]byte{}, d.rest()...))
	if err != nil {
		return nil, errCorrupt
	}
	r.Grant = g
	return r, nil
}

// grantCtr: status | used[2] | windowStart | windowCount[2]. Small and
// updated per message; the immutable grant frame lives under bGrant.
type grantCtr struct {
	Status   uint8
	Used     [2]uint32
	WinStart int64
	WinCount [2]uint16
}

func (c *grantCtr) encode() []byte {
	e := enc{b: make([]byte, 0, 21)}
	e.u8(c.Status)
	e.u32(c.Used[0])
	e.u32(c.Used[1])
	e.i64(c.WinStart)
	e.u16(c.WinCount[0])
	e.u16(c.WinCount[1])
	return e.b
}

func decodeGrantCtr(v []byte) (*grantCtr, error) {
	c := &grantCtr{}
	if v == nil {
		return c, nil
	}
	d := dec{b: v}
	c.Status = d.u8()
	c.Used[0], c.Used[1], c.WinStart = d.u32(), d.u32(), d.i64()
	c.WinCount[0], c.WinCount[1] = d.u16(), d.u16()
	if d.bad {
		return nil, errCorrupt
	}
	return c, nil
}

// msgRec: status | grant | dir | seq | sender | recipient | evseq | expires | ledgerIdx | ackLedgerIdx | ack frame
type msgRec struct {
	Status    uint8
	Grant     wire.ID
	Dir       uint8
	Seq       uint32
	Sender    wire.ID
	Recipient wire.ID
	EvSeq     uint64
	Expires   int64
	LedgerIdx int64
	AckIdx    int64
	AckFrame  []byte
}

func (r *msgRec) encode() []byte {
	e := enc{b: make([]byte, 0, 96+len(r.AckFrame))}
	e.u8(r.Status)
	e.id(r.Grant)
	e.u8(r.Dir)
	e.u32(r.Seq)
	e.id(r.Sender)
	e.id(r.Recipient)
	e.u64(r.EvSeq)
	e.i64(r.Expires)
	e.i64(r.LedgerIdx)
	e.i64(r.AckIdx)
	e.raw(r.AckFrame)
	return e.b
}

func decodeMsg(v []byte) (*msgRec, error) {
	d := dec{b: v}
	r := &msgRec{Status: d.u8(), Grant: d.id(), Dir: d.u8(), Seq: d.u32(), Sender: d.id(), Recipient: d.id(),
		EvSeq: d.u64(), Expires: d.i64(), LedgerIdx: d.i64(), AckIdx: d.i64()}
	if d.bad {
		return nil, errCorrupt
	}
	if rest := d.rest(); len(rest) > 0 {
		r.AckFrame = append([]byte{}, rest...)
	}
	return r, nil
}

// Event is one entry of an agent's inbox stream.
type Event struct {
	Seq       uint64
	Kind      wire.Kind
	Millis    int64
	LedgerIdx int64
	Ref       wire.ID
	Frame     []byte
}

func (ev *Event) encode() []byte {
	e := enc{b: make([]byte, 0, 33+len(ev.Frame))}
	e.u8(uint8(ev.Kind))
	e.i64(ev.Millis)
	e.i64(ev.LedgerIdx)
	e.id(ev.Ref)
	e.raw(ev.Frame)
	return e.b
}

func decodeEvent(seq uint64, v []byte) (*Event, error) {
	d := dec{b: v}
	ev := &Event{Seq: seq, Kind: wire.Kind(d.u8()), Millis: d.i64(), LedgerIdx: d.i64(), Ref: d.id()}
	if d.bad {
		return nil, errCorrupt
	}
	ev.Frame = append([]byte{}, d.rest()...)
	return ev, nil
}

// pressure tracks intros arriving at a recipient: pending count and an hourly window.
type pressure struct {
	Pending  uint32
	WinStart int64
	WinCount uint32
	Prev     uint32
}

func (p *pressure) encode() []byte {
	e := enc{b: make([]byte, 0, 20)}
	e.u32(p.Pending)
	e.i64(p.WinStart)
	e.u32(p.WinCount)
	e.u32(p.Prev)
	return e.b
}

func decodePressure(v []byte) *pressure {
	p := &pressure{}
	if v == nil {
		return p
	}
	d := dec{b: v}
	p.Pending, p.WinStart, p.WinCount, p.Prev = d.u32(), d.i64(), d.u32(), d.u32()
	if d.bad {
		return &pressure{}
	}
	return p
}

// reputation: decaying count of declined/expired intros (milli-units).
type reputation struct {
	Milli   uint32
	Updated int64
}

func (r *reputation) encode() []byte {
	e := enc{b: make([]byte, 0, 12)}
	e.u32(r.Milli)
	e.i64(r.Updated)
	return e.b
}

func decodeReputation(v []byte) *reputation {
	r := &reputation{}
	if v == nil {
		return r
	}
	d := dec{b: v}
	r.Milli, r.Updated = d.u32(), d.i64()
	if d.bad {
		return &reputation{}
	}
	return r
}

func getU64(tx kv.Tx, key []byte) (uint64, error) {
	v, err := tx.Get(key)
	if err != nil || len(v) != 8 {
		return 0, err
	}
	return binary.BigEndian.Uint64(v), nil
}

func addU64(tx kv.Tx, key []byte, delta int64) (uint64, error) {
	v, err := getU64(tx, key)
	if err != nil {
		return 0, err
	}
	n := int64(v) + delta
	if n < 0 {
		n = 0
	}
	return uint64(n), tx.Put(key, kv.U64(uint64(n)))
}

func getU32(tx kv.Tx, key []byte) (uint32, error) {
	v, err := tx.Get(key)
	if err != nil || len(v) != 4 {
		return 0, err
	}
	return binary.BigEndian.Uint32(v), nil
}

func addU32(tx kv.Tx, key []byte, delta int64) error {
	v, err := getU32(tx, key)
	if err != nil {
		return err
	}
	n := int64(v) + delta
	if n < 0 {
		n = 0
	}
	return tx.Put(key, kv.U32(uint32(n)))
}

// agentKey is the compact record checked on every message and ack:
// status | serial | expires | sign key.
type agentKey struct {
	Status  uint8
	Serial  uint32
	Expires int64
	SignPub [wire.PubLen]byte
}

func (k *agentKey) encode() []byte {
	e := enc{b: make([]byte, 0, 45)}
	e.u8(k.Status)
	e.u32(k.Serial)
	e.i64(k.Expires)
	e.raw(k.SignPub[:])
	return e.b
}

func decodeAgentKey(v []byte) (*agentKey, error) {
	d := dec{b: v}
	k := &agentKey{Status: d.u8(), Serial: d.u32(), Expires: d.i64()}
	copy(k.SignPub[:], d.take(wire.PubLen))
	if d.bad {
		return nil, errCorrupt
	}
	return k, nil
}
