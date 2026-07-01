// Package pg is a pure-Go (cgo-free), interpreter-independent reimplementation of
// the deterministic core of Ruby's [pg] gem — the PostgreSQL v3 frontend/backend
// wire-protocol codec, the OID type decoders/encoders, and the PG::Result /
// PG::Connection value surface.
//
// The library owns everything that is a pure function of bytes: encoding the
// frontend messages a client sends (StartupMessage, Query, the extended-query
// Parse/Bind/Describe/Execute/Sync suite, the SCRAM-SHA-256 / MD5 authentication
// math), decoding the backend messages a server replies with, mapping column
// OIDs to Ruby values (matching PG::TextDecoder / PG::BinaryDecoder), and the
// escaping helpers. The TCP/TLS socket is a *host seam*: a [Conn] is driven over
// any [io.ReadWriter] (or a [RoundTripper]), exactly as the go-ruby net-* libms
// inject their transport. No live PostgreSQL server is required to exercise the
// codec — canned backend byte streams decode to the same values a real server
// would produce.
//
// [pg]: https://github.com/ged/ruby-pg
package pg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Frontend message type bytes (the first byte of every frontend message except
// the untyped StartupMessage / SSLRequest / CancelRequest).
const (
	msgBind        = 'B'
	msgClose       = 'C'
	msgCopyData    = 'd'
	msgCopyDone    = 'c'
	msgCopyFail    = 'f'
	msgDescribe    = 'D'
	msgExecute     = 'E'
	msgFlush       = 'H'
	msgFuncCall    = 'F'
	msgParse       = 'P'
	msgPassword    = 'p' // PasswordMessage / SASLInitialResponse / SASLResponse / GSSResponse
	msgQuery       = 'Q'
	msgSync        = 'S'
	msgTerminate   = 'X'
)

// Backend message type bytes.
const (
	msgAuthentication  = 'R'
	msgBackendKeyData  = 'K'
	msgBindComplete    = '2'
	msgCloseComplete   = '3'
	msgCommandComplete = 'C'
	msgCopyBothResp    = 'W'
	msgCopyInResp      = 'G'
	msgCopyOutResp     = 'H'
	msgDataRow         = 'D'
	msgEmptyQuery      = 'I'
	msgErrorResponse   = 'E'
	msgFuncCallResp    = 'V'
	msgNoData          = 'n'
	msgNoticeResponse  = 'N'
	msgNotification    = 'A'
	msgParamDescription = 't'
	msgParameterStatus = 'S'
	msgParseComplete   = '1'
	msgPortalSuspended = 's'
	msgReadyForQuery   = 'Z'
	msgRowDescription  = 'T'
)

// Authentication sub-request codes (the int32 that follows an 'R' message).
const (
	authOK                = 0
	authKerberosV5        = 2
	authCleartextPassword = 3
	authMD5Password       = 5
	authSCMCredential     = 6
	authGSS               = 7
	authGSSContinue       = 8
	authSSPI              = 9
	authSASL              = 10
	authSASLContinue      = 11
	authSASLFinal         = 12
)

// The protocol version negotiated in the StartupMessage: major 3, minor 0.
const protocolVersion = 196608 // (3 << 16) | 0

// TransactionStatus is the single byte a ReadyForQuery message carries.
type TransactionStatus byte

const (
	// TxnIdle means not in a transaction block ('I').
	TxnIdle TransactionStatus = 'I'
	// TxnActive means in a transaction block ('T').
	TxnActive TransactionStatus = 'T'
	// TxnError means in a failed transaction block ('E'); queries are rejected
	// until the block ends.
	TxnError TransactionStatus = 'E'
)

// Format is the wire format of a parameter or column: text or binary.
type Format int16

const (
	// TextFormat (0) is PostgreSQL's default human-readable representation.
	TextFormat Format = 0
	// BinaryFormat (1) is the type's binary representation.
	BinaryFormat Format = 1
)

var (
	// errShort is returned when a buffer is truncated mid-field.
	errShort = errors.New("pg: message truncated")
	// errBadType is returned when a message's type byte does not match what a
	// decoder expected.
	errBadType = errors.New("pg: unexpected message type")
)

// writeBuf accumulates a frontend message body and frames it with its type byte
// and Int32 length prefix. PostgreSQL frame length counts the length field
// itself but not the type byte.
type writeBuf struct {
	b []byte
}

func (w *writeBuf) byte(v byte)  { w.b = append(w.b, v) }
func (w *writeBuf) bytes(v []byte) { w.b = append(w.b, v...) }

func (w *writeBuf) int16(v int16) {
	w.b = append(w.b, byte(v>>8), byte(v))
}

func (w *writeBuf) int32(v int32) {
	w.b = append(w.b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// string writes a NUL-terminated C string.
func (w *writeBuf) string(s string) {
	w.b = append(w.b, s...)
	w.b = append(w.b, 0)
}

// frame prepends msgType and the Int32 length and returns the full message. A
// zero msgType produces an untyped message (StartupMessage / SSLRequest), whose
// length still counts the length field.
func (w *writeBuf) frame(msgType byte) []byte {
	body := w.b
	if msgType == 0 {
		out := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(out, uint32(4+len(body)))
		copy(out[4:], body)
		return out
	}
	out := make([]byte, 1+4+len(body))
	out[0] = msgType
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

// readBuf consumes a backend message body (the bytes after the type byte and
// length prefix have been stripped by the framer).
type readBuf struct {
	b   []byte
	err error
}

func (r *readBuf) fail() bool { return r.err != nil }

func (r *readBuf) byte() byte {
	if r.err != nil {
		return 0
	}
	if len(r.b) < 1 {
		r.err = errShort
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *readBuf) int16() int16 {
	if r.err != nil {
		return 0
	}
	if len(r.b) < 2 {
		r.err = errShort
		return 0
	}
	v := int16(binary.BigEndian.Uint16(r.b))
	r.b = r.b[2:]
	return v
}

func (r *readBuf) int32() int32 {
	if r.err != nil {
		return 0
	}
	if len(r.b) < 4 {
		r.err = errShort
		return 0
	}
	v := int32(binary.BigEndian.Uint32(r.b))
	r.b = r.b[4:]
	return v
}

// string reads a NUL-terminated C string.
func (r *readBuf) string() string {
	if r.err != nil {
		return ""
	}
	for i, c := range r.b {
		if c == 0 {
			s := string(r.b[:i])
			r.b = r.b[i+1:]
			return s
		}
	}
	r.err = errShort
	return ""
}

// next reads exactly n bytes.
func (r *readBuf) next(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errShort
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

// float64 is a helper for binary float decoding.
func float64bits(u uint64) float64 { return math.Float64frombits(u) }
func float32bits(u uint32) float32 { return math.Float32frombits(u) }

// String makes TransactionStatus printable for diagnostics.
func (t TransactionStatus) String() string {
	switch t {
	case TxnIdle:
		return "idle"
	case TxnActive:
		return "active"
	case TxnError:
		return "error"
	default:
		return fmt.Sprintf("unknown(%q)", byte(t))
	}
}
