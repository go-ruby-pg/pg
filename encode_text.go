package pg

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"
)

// This file encodes a Ruby value to the *text* wire format PostgreSQL accepts
// for a bound parameter, matching PG::TextEncoder::*. A nil value is SQL NULL,
// represented on the Bind wire as a -1 length; EncodeParam returns (nil, nil) for
// it so the caller emits a NULL BindParam.

// EncodeParam renders v as the text bytes of a query parameter. Supported Go
// types: nil, bool, all signed/unsigned integers, *big.Int, float32/float64,
// string, []byte (bytea, hex-encoded), time.Time, *big.Rat (numeric), and []any
// (a PostgreSQL array literal). A nil result means SQL NULL.
func EncodeParam(v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case bool:
		if t {
			return []byte("t"), nil
		}
		return []byte("f"), nil
	case int:
		return []byte(strconv.FormatInt(int64(t), 10)), nil
	case int8:
		return []byte(strconv.FormatInt(int64(t), 10)), nil
	case int16:
		return []byte(strconv.FormatInt(int64(t), 10)), nil
	case int32:
		return []byte(strconv.FormatInt(int64(t), 10)), nil
	case int64:
		return []byte(strconv.FormatInt(t, 10)), nil
	case uint:
		return []byte(strconv.FormatUint(uint64(t), 10)), nil
	case uint8:
		return []byte(strconv.FormatUint(uint64(t), 10)), nil
	case uint16:
		return []byte(strconv.FormatUint(uint64(t), 10)), nil
	case uint32:
		return []byte(strconv.FormatUint(uint64(t), 10)), nil
	case uint64:
		return []byte(strconv.FormatUint(t, 10)), nil
	case *big.Int:
		return []byte(t.String()), nil
	case float32:
		return []byte(encodeFloat(float64(t))), nil
	case float64:
		return []byte(encodeFloat(t)), nil
	case *big.Rat:
		// Render an exact decimal where terminating, else a high-precision one.
		return []byte(t.FloatString(ratScale(t))), nil
	case string:
		return []byte(t), nil
	case []byte:
		return encodeByteaHex(t), nil
	case time.Time:
		return []byte(t.Format("2006-01-02 15:04:05.999999999-07:00")), nil
	case []any:
		s, err := encodeArrayLiteral(t)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return nil, fmt.Errorf("pg: cannot encode %T as a parameter", v)
}

// encodeFloat matches PostgreSQL's float text: Infinity / -Infinity / NaN, and
// the shortest round-trippable decimal otherwise.
func encodeFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// ratScale picks a decimal scale for a *big.Rat: exact when the denominator is
// 2^a*5^b (a terminating decimal), else a fixed high precision.
func ratScale(r *big.Rat) int {
	den := new(big.Int).Set(r.Denom())
	scale := 0
	two := big.NewInt(2)
	five := big.NewInt(5)
	zero := big.NewInt(0)
	m := new(big.Int)
	for den.Cmp(big.NewInt(1)) > 0 && scale < 100 {
		if m.Mod(den, two).Cmp(zero) == 0 {
			den.Div(den, two)
		} else if m.Mod(den, five).Cmp(zero) == 0 {
			den.Div(den, five)
		} else {
			return 30 // non-terminating; use a wide fixed precision
		}
		scale++
	}
	return scale
}

// encodeByteaHex renders bytes as PostgreSQL's \x hex bytea literal.
func encodeByteaHex(b []byte) []byte {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 2+2*len(b))
	out[0] = '\\'
	out[1] = 'x'
	for i, c := range b {
		out[2+2*i] = hexdigits[c>>4]
		out[3+2*i] = hexdigits[c&0x0f]
	}
	return out
}

// encodeArrayLiteral renders a nested []any as a PostgreSQL array literal
// {a,b,{c,d}}. Elements are encoded via EncodeParam and quoted when they contain
// characters the array grammar treats specially; nil becomes NULL.
func encodeArrayLiteral(a []any) (string, error) {
	out := make([]byte, 0, 2+len(a)*4)
	out = append(out, '{')
	for i, e := range a {
		if i > 0 {
			out = append(out, ',')
		}
		if e == nil {
			out = append(out, "NULL"...)
			continue
		}
		if sub, ok := e.([]any); ok {
			s, err := encodeArrayLiteral(sub)
			if err != nil {
				return "", err
			}
			out = append(out, s...)
			continue
		}
		raw, err := EncodeParam(e)
		if err != nil {
			return "", err
		}
		out = append(out, quoteArrayElem(raw)...)
	}
	out = append(out, '}')
	return string(out), nil
}

// quoteArrayElem double-quotes and backslash-escapes an element when it contains
// a delimiter, brace, quote, backslash, whitespace, or is the literal NULL /
// empty (which would otherwise be ambiguous).
func quoteArrayElem(raw []byte) []byte {
	need := len(raw) == 0 || string(raw) == "NULL"
	for _, c := range raw {
		switch c {
		case '{', '}', ',', '"', '\\', ' ', '\t', '\n', '\r':
			need = true
		}
	}
	if !need {
		return raw
	}
	out := make([]byte, 0, len(raw)+2)
	out = append(out, '"')
	for _, c := range raw {
		if c == '"' || c == '\\' {
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	out = append(out, '"')
	return out
}
