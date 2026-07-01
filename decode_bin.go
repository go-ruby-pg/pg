package pg

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// This file decodes the *binary* wire format (format code 1) of a column value,
// matching PG::BinaryDecoder::*. Binary integers/floats are big-endian; bool is
// a single byte; bytea/text/json are raw bytes; timestamps are microseconds
// since the PostgreSQL epoch (2000-01-01).

// pgEpoch is 2000-01-01T00:00:00Z, the origin PostgreSQL's binary timestamps
// count microseconds from.
var pgEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// DecodeBinary decodes a non-NULL binary-format value of the given OID. Unknown
// OIDs fall back to the raw bytes as a string.
func DecodeBinary(oid OID, raw []byte) (any, error) {
	switch oid {
	case OIDBool:
		return decodeBoolBin(raw)
	case OIDInt2:
		if len(raw) != 2 {
			return nil, errShort
		}
		return int64(int16(binary.BigEndian.Uint16(raw))), nil
	case OIDInt4, OIDOID, OIDXID, OIDCID:
		if len(raw) != 4 {
			return nil, errShort
		}
		return int64(int32(binary.BigEndian.Uint32(raw))), nil
	case OIDInt8:
		if len(raw) != 8 {
			return nil, errShort
		}
		return int64(binary.BigEndian.Uint64(raw)), nil
	case OIDFloat4:
		if len(raw) != 4 {
			return nil, errShort
		}
		return float64(float32bits(binary.BigEndian.Uint32(raw))), nil
	case OIDFloat8:
		if len(raw) != 8 {
			return nil, errShort
		}
		return float64bits(binary.BigEndian.Uint64(raw)), nil
	case OIDNumeric:
		return decodeNumericBin(raw)
	case OIDDate:
		return decodeDateBin(raw)
	case OIDTimestamp, OIDTimestamptz:
		return decodeTimestampBin(raw)
	case OIDBytea:
		return append([]byte(nil), raw...), nil
	case OIDText, OIDVarchar, OIDBPChar, OIDName, OIDChar,
		OIDJSON, OIDUUID, OIDUnknown, OIDXML:
		return string(raw), nil
	case OIDJSONB:
		return decodeJSONBBin(raw)
	}
	if elem, ok := arrayElem(oid); ok {
		return decodeArrayBin(elem, raw)
	}
	return string(raw), nil
}

func decodeBoolBin(raw []byte) (any, error) {
	if len(raw) != 1 {
		return nil, errShort
	}
	return raw[0] != 0, nil
}

// decodeJSONBBin strips the leading version byte (1) of the jsonb binary format
// and returns the JSON text.
func decodeJSONBBin(raw []byte) (any, error) {
	if len(raw) < 1 {
		return nil, errShort
	}
	if raw[0] != 1 {
		return nil, fmt.Errorf("pg: unsupported jsonb version %d", raw[0])
	}
	return string(raw[1:]), nil
}

func decodeDateBin(raw []byte) (any, error) {
	if len(raw) != 4 {
		return nil, errShort
	}
	days := int32(binary.BigEndian.Uint32(raw))
	return pgEpoch.AddDate(0, 0, int(days)), nil
}

func decodeTimestampBin(raw []byte) (any, error) {
	if len(raw) != 8 {
		return nil, errShort
	}
	micros := int64(binary.BigEndian.Uint64(raw))
	return pgEpoch.Add(time.Duration(micros) * time.Microsecond), nil
}

// numeric binary sign flags.
const (
	numericPos    = 0x0000
	numericNeg    = 0x4000
	numericNaN    = 0xC000
	numericPInf   = 0xD000
	numericNInf   = 0xF000
	numericNBase  = 10000
	numericDScale = 4
)

// decodeNumericBin decodes the binary numeric format into a *big.Rat (or the
// string "NaN"/"Infinity"/"-Infinity" for the special values).
func decodeNumericBin(raw []byte) (any, error) {
	if len(raw) < 8 {
		return nil, errShort
	}
	ndigits := int(binary.BigEndian.Uint16(raw[0:2]))
	weight := int16(binary.BigEndian.Uint16(raw[2:4]))
	sign := binary.BigEndian.Uint16(raw[4:6])
	// dscale := binary.BigEndian.Uint16(raw[6:8]) // display scale; value is exact
	if len(raw) != 8+2*ndigits {
		return nil, errShort
	}
	switch sign {
	case numericNaN:
		return "NaN", nil
	case numericPInf:
		return "Infinity", nil
	case numericNInf:
		return "-Infinity", nil
	}
	// Reconstruct the exact rational: sum digit[i] * 10000^(weight-i).
	acc := new(big.Rat)
	base := big.NewInt(numericNBase)
	for i := 0; i < ndigits; i++ {
		d := int64(binary.BigEndian.Uint16(raw[8+2*i : 10+2*i]))
		exp := int(weight) - i
		term := new(big.Rat).SetInt64(d)
		pw := ratPow(base, exp)
		term.Mul(term, pw)
		acc.Add(acc, term)
	}
	if sign == numericNeg {
		acc.Neg(acc)
	}
	return acc, nil
}

// ratPow returns base**exp as a *big.Rat, handling negative exponents.
func ratPow(base *big.Int, exp int) *big.Rat {
	if exp == 0 {
		return big.NewRat(1, 1)
	}
	n := exp
	if n < 0 {
		n = -n
	}
	p := new(big.Int).Exp(base, big.NewInt(int64(n)), nil)
	if exp < 0 {
		return new(big.Rat).SetFrac(big.NewInt(1), p)
	}
	return new(big.Rat).SetInt(p)
}

// decodeArrayBin decodes the binary array format: an Int32 dimension count, an
// Int32 has-null flag, an element OID, then per-dimension length/lower-bound
// pairs, then the flattened Int32-length-prefixed element values, which are
// reshaped into nested []any per the dimension lengths.
func decodeArrayBin(elem OID, raw []byte) (any, error) {
	r := &readBuf{b: raw}
	ndim := int(r.int32())
	_ = r.int32() // has-null flag
	_ = r.int32() // element OID (trusted from column type instead)
	if r.fail() {
		return nil, r.err
	}
	if ndim < 0 {
		return nil, fmt.Errorf("pg: negative array dimensions %d", ndim)
	}
	if ndim == 0 {
		return []any{}, nil
	}
	total := 1
	dims := make([]int, ndim)
	for i := 0; i < ndim; i++ {
		d := int(r.int32())
		_ = r.int32() // lower bound
		if d < 0 {
			return nil, fmt.Errorf("pg: negative array dimension length %d", d)
		}
		dims[i] = d
		total *= d
	}
	if r.fail() {
		return nil, r.err
	}
	flat := make([]any, 0, total)
	for i := 0; i < total; i++ {
		length := int(r.int32())
		if length < 0 {
			flat = append(flat, nil)
			continue
		}
		b := r.next(length)
		if r.fail() {
			return nil, r.err
		}
		v, err := DecodeBinary(elem, b)
		if err != nil {
			return nil, err
		}
		flat = append(flat, v)
	}
	if r.fail() {
		return nil, r.err
	}
	return reshape(flat, dims), nil
}

// reshape folds a flat slice into a nested []any matching dims. reshape of a
// 1-element dims is the flat slice itself; otherwise it groups by the last
// dimension repeatedly, innermost first.
func reshape(flat []any, dims []int) any {
	if len(dims) == 1 {
		return flat
	}
	inner := dims[len(dims)-1]
	grouped := make([]any, 0, len(flat)/inner)
	for i := 0; i < len(flat); i += inner {
		grouped = append(grouped, flat[i:i+inner])
	}
	return reshape(grouped, dims[:len(dims)-1])
}
