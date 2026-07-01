package pg

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// This file decodes the *text* wire format (format code 0) of a column value to
// a Ruby value, matching PG::TextDecoder::*. The value model mirrors the one the
// pg gem hands back when a type map is installed: Integer→int64/*big.Int,
// Float→float64, Boolean→bool, Numeric→*big.Rat via a decimal string, bytea→raw
// []byte, timestamps→time.Time, uuid/json/text→string, arrays→[]any.

// errNull is a sentinel a decoder never returns; NULL is handled by the caller
// (a nil raw slice decodes to nil before dispatch).
var errNull = errors.New("pg: null value")

// DecodeText decodes a non-NULL text-format value of the given OID. Unknown OIDs
// fall back to the raw string, exactly as PG::TextDecoder::String would.
func DecodeText(oid OID, raw []byte) (any, error) {
	switch oid {
	case OIDBool:
		return decodeBoolText(raw)
	case OIDInt2, OIDInt4, OIDInt8, OIDOID, OIDXID, OIDCID:
		return decodeIntText(raw)
	case OIDFloat4, OIDFloat8:
		return decodeFloatText(raw)
	case OIDNumeric:
		return decodeNumericText(raw)
	case OIDBytea:
		return decodeByteaText(raw)
	case OIDDate:
		return decodeDateText(raw)
	case OIDTimestamp:
		return decodeTimestampText(raw, false)
	case OIDTimestamptz:
		return decodeTimestampText(raw, true)
	case OIDText, OIDVarchar, OIDBPChar, OIDName, OIDChar,
		OIDJSON, OIDJSONB, OIDUUID, OIDUnknown, OIDXML:
		return string(raw), nil
	}
	if elem, ok := arrayElem(oid); ok {
		return decodeArrayText(elem, raw)
	}
	return string(raw), nil
}

func decodeBoolText(raw []byte) (any, error) {
	switch string(raw) {
	case "t":
		return true, nil
	case "f":
		return false, nil
	}
	return nil, fmt.Errorf("pg: invalid bool text %q", raw)
}

// decodeIntText returns an int64 when the value fits, else a *big.Int (matching
// Ruby's automatic Integer→Bignum promotion).
func decodeIntText(raw []byte) (any, error) {
	s := string(raw)
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, nil
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("pg: invalid integer text %q", raw)
	}
	return bi, nil
}

func decodeFloatText(raw []byte) (any, error) {
	s := string(raw)
	switch s {
	case "NaN":
		return nan(), nil
	case "Infinity":
		return posInf(), nil
	case "-Infinity":
		return negInf(), nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, fmt.Errorf("pg: invalid float text %q", raw)
	}
	return v, nil
}

// decodeNumericText returns a *big.Rat, an exact decimal PG::TextDecoder::Numeric
// would hand back as a Ruby BigDecimal. Special "NaN" yields the string "NaN".
func decodeNumericText(raw []byte) (any, error) {
	s := string(raw)
	if s == "NaN" {
		return "NaN", nil
	}
	r := new(big.Rat)
	if _, ok := r.SetString(s); !ok {
		return nil, fmt.Errorf("pg: invalid numeric text %q", raw)
	}
	return r, nil
}

// decodeByteaText decodes the hex (\x...) and legacy escape formats.
func decodeByteaText(raw []byte) (any, error) {
	if len(raw) >= 2 && raw[0] == '\\' && raw[1] == 'x' {
		out := make([]byte, 0, (len(raw)-2)/2)
		hexs := raw[2:]
		if len(hexs)%2 != 0 {
			return nil, errors.New("pg: odd-length bytea hex")
		}
		for i := 0; i < len(hexs); i += 2 {
			hi, ok1 := fromHex(hexs[i])
			lo, ok2 := fromHex(hexs[i+1])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("pg: invalid bytea hex %q", raw)
			}
			out = append(out, hi<<4|lo)
		}
		return out, nil
	}
	return decodeByteaEscape(raw)
}

// decodeByteaEscape decodes the pre-9.0 escape format: \\ → \, \nnn → octal, and
// everything else literal.
func decodeByteaEscape(raw []byte) (any, error) {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '\\' {
			out = append(out, '\\')
			i++
			continue
		}
		if i+3 < len(raw) &&
			raw[i+1] >= '0' && raw[i+1] <= '7' &&
			raw[i+2] >= '0' && raw[i+2] <= '7' &&
			raw[i+3] >= '0' && raw[i+3] <= '7' {
			v := (raw[i+1]-'0')<<6 | (raw[i+2]-'0')<<3 | (raw[i+3] - '0')
			out = append(out, v)
			i += 3
			continue
		}
		return nil, fmt.Errorf("pg: invalid bytea escape at %d", i)
	}
	return out, nil
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func decodeDateText(raw []byte) (any, error) {
	t, err := time.Parse("2006-01-02", string(raw))
	if err != nil {
		return nil, fmt.Errorf("pg: invalid date %q", raw)
	}
	return t, nil
}

// decodeTimestampText parses PostgreSQL's default ISO datestyle. With tz, a
// numeric offset (e.g. +00, +05:30) is present; without, the value is naive and
// interpreted as UTC wall-clock.
func decodeTimestampText(raw []byte, withTZ bool) (any, error) {
	s := string(raw)
	// Fractional seconds are optional and variable-width.
	layouts := []string{
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
	}
	if !withTZ {
		layouts = []string{"2006-01-02 15:04:05.999999999"}
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return nil, fmt.Errorf("pg: invalid timestamp %q", raw)
}

// decodeArrayText parses the {a,b,{c,d}} array literal into nested []any,
// decoding each element with the element OID. NULL elements become nil.
func decodeArrayText(elem OID, raw []byte) (any, error) {
	p := &arrayParser{s: string(raw), elem: elem}
	v, err := p.parse()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.s) {
		return nil, fmt.Errorf("pg: trailing data in array %q", raw)
	}
	return v, nil
}

type arrayParser struct {
	s    string
	pos  int
	elem OID
}

func (p *arrayParser) skipSpace() {
	for p.pos < len(p.s) && p.s[p.pos] == ' ' {
		p.pos++
	}
}

func (p *arrayParser) parse() (any, error) {
	p.skipSpace()
	if p.pos >= len(p.s) {
		return nil, errors.New("pg: empty array literal")
	}
	if p.s[p.pos] != '{' {
		return nil, fmt.Errorf("pg: array literal must start with '{' near %d", p.pos)
	}
	return p.parseBrace()
}

func (p *arrayParser) parseBrace() (any, error) {
	p.pos++ // consume '{'
	out := []any{}
	p.skipSpace()
	if p.pos < len(p.s) && p.s[p.pos] == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.s) {
			return nil, errors.New("pg: unterminated array")
		}
		var elem any
		var err error
		if p.s[p.pos] == '{' {
			elem, err = p.parseBrace()
		} else {
			elem, err = p.parseScalar()
		}
		if err != nil {
			return nil, err
		}
		out = append(out, elem)
		p.skipSpace()
		if p.pos >= len(p.s) {
			return nil, errors.New("pg: unterminated array")
		}
		switch p.s[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return out, nil
		default:
			return nil, fmt.Errorf("pg: unexpected %q in array", p.s[p.pos])
		}
	}
}

func (p *arrayParser) parseScalar() (any, error) {
	if p.s[p.pos] == '"' {
		return p.parseQuoted()
	}
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == ',' || c == '}' {
			break
		}
		p.pos++
	}
	tok := strings.TrimRight(p.s[start:p.pos], " ")
	if tok == "NULL" {
		return nil, nil
	}
	return DecodeText(p.elem, []byte(tok))
}

func (p *arrayParser) parseQuoted() (any, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch c {
		case '\\':
			p.pos++
			if p.pos >= len(p.s) {
				return nil, errors.New("pg: dangling escape in array")
			}
			b.WriteByte(p.s[p.pos])
			p.pos++
		case '"':
			p.pos++
			return DecodeText(p.elem, []byte(b.String()))
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return nil, errors.New("pg: unterminated quoted array element")
}
