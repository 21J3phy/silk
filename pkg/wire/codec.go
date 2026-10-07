// Package wire defines Silk protocol v2 objects and their canonical binary
// encoding. Every object has exactly one valid encoding: fixed field order,
// big-endian integers, explicit length prefixes, and no trailing bytes. A
// signature always covers a domain-separation string followed by every byte
// of the object that precedes the signature.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrMalformed is returned for any encoding that is not canonical or exceeds a bound.
var ErrMalformed = errors.New("malformed frame")

type writer struct{ b []byte }

func (w *writer) u8(v uint8)   { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *writer) i64(v int64)  { w.u64(uint64(v)) }
func (w *writer) raw(p []byte) { w.b = append(w.b, p...) }
func (w *writer) str8(s string) {
	w.u8(uint8(len(s)))
	w.b = append(w.b, s...)
}
func (w *writer) bytes16(p []byte) {
	w.u16(uint16(len(p)))
	w.b = append(w.b, p...)
}
func (w *writer) bytes32(p []byte) {
	w.u32(uint32(len(p)))
	w.b = append(w.b, p...)
}

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b)-r.off < n {
		r.fail("truncated at byte %d", r.off)
		return nil
	}
	p := r.b[r.off : r.off+n : r.off+n]
	r.off += n
	return p
}

func (r *reader) u8() uint8 {
	p := r.take(1)
	if p == nil {
		return 0
	}
	return p[0]
}

func (r *reader) u16() uint16 {
	p := r.take(2)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint16(p)
}

func (r *reader) u32() uint32 {
	p := r.take(4)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint32(p)
}

func (r *reader) u64() uint64 {
	p := r.take(8)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint64(p)
}

func (r *reader) i64() int64 { return int64(r.u64()) }

func (r *reader) fixed(dst []byte) { copy(dst, r.take(len(dst))) }

func (r *reader) str8(min, max int, valid func(string) bool, field string) string {
	n := int(r.u8())
	if r.err == nil && (n < min || n > max) {
		r.fail("%s length %d outside %d..%d", field, n, min, max)
	}
	p := r.take(n)
	if r.err != nil {
		return ""
	}
	s := string(p)
	if n > 0 && valid != nil && !valid(s) {
		r.fail("%s has invalid characters", field)
	}
	return s
}

func (r *reader) bytes16(min, max int, field string) []byte {
	n := int(r.u16())
	if r.err == nil && (n < min || n > max) {
		r.fail("%s length %d outside %d..%d", field, n, min, max)
	}
	return r.take(n)
}

func (r *reader) bytes32(min, max int, field string) []byte {
	n := r.u32()
	if r.err == nil && (int64(n) < int64(min) || int64(n) > int64(max)) {
		r.fail("%s length %d outside %d..%d", field, n, min, max)
	}
	return r.take(int(n))
}

func (r *reader) header(kind Kind) {
	if v := r.u8(); r.err == nil && v != Version {
		r.fail("unsupported version %d", v)
	}
	if k := Kind(r.u8()); r.err == nil && k != kind {
		r.fail("expected %s, got kind %d", kind, k)
	}
}

func (r *reader) done() error {
	if r.err == nil && r.off != len(r.b) {
		r.fail("%d trailing bytes", len(r.b)-r.off)
	}
	return r.err
}

// PeekKind reports the kind of a frame without decoding it.
func PeekKind(frame []byte) (Kind, error) {
	if len(frame) < 2 || frame[0] != Version {
		return 0, fmt.Errorf("%w: missing or unsupported version", ErrMalformed)
	}
	return Kind(frame[1]), nil
}
