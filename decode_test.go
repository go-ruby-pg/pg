package pg

import (
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestDecodeTextScalars(t *testing.T) {
	cases := []struct {
		oid  OID
		raw  string
		want any
	}{
		{OIDBool, "t", true},
		{OIDBool, "f", false},
		{OIDInt4, "42", int64(42)},
		{OIDInt8, "-9", int64(-9)},
		{OIDOID, "100", int64(100)},
		{OIDText, "hi", "hi"},
		{OIDVarchar, "vc", "vc"},
		{OIDJSON, `{"a":1}`, `{"a":1}`},
		{OIDUUID, "abc", "abc"},
		{OIDFloat8, "3.5", 3.5},
	}
	for _, c := range cases {
		got, err := DecodeText(c.oid, []byte(c.raw))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("DecodeText(%d,%q)=%v,%v want %v", c.oid, c.raw, got, err, c.want)
		}
	}
}

func TestDecodeTextBigInt(t *testing.T) {
	got, err := DecodeText(OIDInt8, []byte("99999999999999999999999999"))
	if err != nil {
		t.Fatal(err)
	}
	bi, ok := got.(*big.Int)
	if !ok || bi.String() != "99999999999999999999999999" {
		t.Errorf("bigint decode: %v", got)
	}
	if _, err := DecodeText(OIDInt4, []byte("xx")); err == nil {
		t.Errorf("want int parse error")
	}
}

func TestDecodeTextFloatSpecials(t *testing.T) {
	for raw, check := range map[string]func(float64) bool{
		"NaN":       math.IsNaN,
		"Infinity":  func(f float64) bool { return math.IsInf(f, 1) },
		"-Infinity": func(f float64) bool { return math.IsInf(f, -1) },
	} {
		got, err := DecodeText(OIDFloat8, []byte(raw))
		if err != nil || !check(got.(float64)) {
			t.Errorf("float special %q: %v %v", raw, got, err)
		}
	}
	if _, err := DecodeText(OIDFloat4, []byte("nope")); err == nil {
		t.Errorf("want float parse error")
	}
	if _, err := DecodeText(OIDBool, []byte("x")); err == nil {
		t.Errorf("want bool error")
	}
}

func TestDecodeTextNumeric(t *testing.T) {
	got, err := DecodeText(OIDNumeric, []byte("3.14"))
	if err != nil {
		t.Fatal(err)
	}
	r := got.(*big.Rat)
	if r.FloatString(2) != "3.14" {
		t.Errorf("numeric: %v", r)
	}
	if got, _ := DecodeText(OIDNumeric, []byte("NaN")); got != "NaN" {
		t.Errorf("numeric NaN: %v", got)
	}
	if _, err := DecodeText(OIDNumeric, []byte("bad")); err == nil {
		t.Errorf("want numeric error")
	}
}

func TestDecodeTextBytea(t *testing.T) {
	got, err := DecodeText(OIDBytea, []byte(`\x0a1b`))
	if err != nil || !reflect.DeepEqual(got, []byte{0x0a, 0x1b}) {
		t.Errorf("bytea hex: %v %v", got, err)
	}
	// escape format: \\ and octal and literal.
	got, err = DecodeText(OIDBytea, []byte(`ab\\\001c`))
	if err != nil || !reflect.DeepEqual(got, []byte{'a', 'b', '\\', 1, 'c'}) {
		t.Errorf("bytea escape: %v %v", got, err)
	}
	if _, err := DecodeText(OIDBytea, []byte(`\x0`)); err == nil {
		t.Errorf("odd hex should error")
	}
	if _, err := DecodeText(OIDBytea, []byte(`\xzz`)); err == nil {
		t.Errorf("bad hex should error")
	}
	if _, err := DecodeText(OIDBytea, []byte(`\z`)); err == nil {
		t.Errorf("bad escape should error")
	}
}

func TestDecodeTextDateTimestamp(t *testing.T) {
	got, err := DecodeText(OIDDate, []byte("2026-07-01"))
	if err != nil || !got.(time.Time).Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("date: %v %v", got, err)
	}
	if _, err := DecodeText(OIDDate, []byte("nope")); err == nil {
		t.Errorf("bad date")
	}
	got, err = DecodeText(OIDTimestamp, []byte("2026-07-01 12:30:00"))
	if err != nil {
		t.Fatalf("ts: %v", err)
	}
	if !got.(time.Time).Equal(time.Date(2026, 7, 1, 12, 30, 0, 0, time.UTC)) {
		t.Errorf("timestamp: %v", got)
	}
	got, err = DecodeText(OIDTimestamptz, []byte("2026-07-01 12:30:00.5+02"))
	if err != nil {
		t.Fatalf("tstz: %v", err)
	}
	if _, err := DecodeText(OIDTimestamp, []byte("bad")); err == nil {
		t.Errorf("bad timestamp")
	}
	if _, err := DecodeText(OIDTimestamptz, []byte("bad")); err == nil {
		t.Errorf("bad tstz")
	}
}

func TestDecodeTextArray(t *testing.T) {
	got, err := DecodeText(OIDInt4Array, []byte("{1,2,3}"))
	if err != nil || !reflect.DeepEqual(got, []any{int64(1), int64(2), int64(3)}) {
		t.Errorf("int array: %v %v", got, err)
	}
	got, _ = DecodeText(OIDTextArray, []byte(`{a,"b,c",NULL}`))
	if !reflect.DeepEqual(got, []any{"a", "b,c", nil}) {
		t.Errorf("text array: %v", got)
	}
	got, _ = DecodeText(OIDInt4Array, []byte("{{1,2},{3,4}}"))
	if !reflect.DeepEqual(got, []any{[]any{int64(1), int64(2)}, []any{int64(3), int64(4)}}) {
		t.Errorf("nested array: %v", got)
	}
	got, _ = DecodeText(OIDInt4Array, []byte("{}"))
	if !reflect.DeepEqual(got, []any{}) {
		t.Errorf("empty array: %v", got)
	}
	got, _ = DecodeText(OIDTextArray, []byte(`{" a\"b "}`))
	if !reflect.DeepEqual(got, []any{` a"b `}) {
		t.Errorf("quoted escape array: %v", got)
	}
	// error cases
	for _, bad := range []string{"", "1,2", "{1,2", "{1 2}", `{"a`, `{"a\`, "{1,2}x"} {
		if _, err := DecodeText(OIDInt4Array, []byte(bad)); err == nil {
			t.Errorf("array %q should error", bad)
		}
	}
	// element decode error propagates
	if _, err := DecodeText(OIDInt4Array, []byte("{x}")); err == nil {
		t.Errorf("bad element should error")
	}
}

func TestDecodeTextUnknownFallback(t *testing.T) {
	got, err := DecodeText(OID(999999), []byte("raw"))
	if err != nil || got != "raw" {
		t.Errorf("fallback: %v %v", got, err)
	}
}

func TestDecodeBinaryScalars(t *testing.T) {
	be16 := func(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
	be32 := func(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	be64 := func(v uint64) []byte {
		b := make([]byte, 8)
		for i := 7; i >= 0; i-- {
			b[i] = byte(v)
			v >>= 8
		}
		return b
	}
	if v, _ := DecodeBinary(OIDBool, []byte{1}); v != true {
		t.Errorf("bin bool")
	}
	if v, _ := DecodeBinary(OIDInt2, be16(uint16(0xFFFB))); v != int64(-5) { // -5 as int16
		t.Errorf("bin int2: %v", v)
	}
	if v, _ := DecodeBinary(OIDInt4, be32(0xFFFFFFF9)); v != int64(-7) { // -7 as int32
		t.Errorf("bin int4")
	}
	if v, _ := DecodeBinary(OIDInt8, be64(uint64(123))); v != int64(123) {
		t.Errorf("bin int8")
	}
	if v, _ := DecodeBinary(OIDFloat4, be32(math.Float32bits(1.5))); v != 1.5 {
		t.Errorf("bin float4")
	}
	if v, _ := DecodeBinary(OIDFloat8, be64(math.Float64bits(2.5))); v != 2.5 {
		t.Errorf("bin float8")
	}
	if v, _ := DecodeBinary(OIDText, []byte("hi")); v != "hi" {
		t.Errorf("bin text")
	}
	if v, _ := DecodeBinary(OIDBytea, []byte{9, 8}); !reflect.DeepEqual(v, []byte{9, 8}) {
		t.Errorf("bin bytea")
	}
	if v, _ := DecodeBinary(OIDJSONB, append([]byte{1}, []byte(`{"a":1}`)...)); v != `{"a":1}` {
		t.Errorf("bin jsonb")
	}
	if v, _ := DecodeBinary(OID(999999), []byte("x")); v != "x" {
		t.Errorf("bin fallback")
	}
}

func TestDecodeBinaryErrors(t *testing.T) {
	shortCases := []OID{OIDInt2, OIDInt4, OIDInt8, OIDFloat4, OIDFloat8, OIDDate, OIDTimestamp}
	for _, oid := range shortCases {
		if _, err := DecodeBinary(oid, []byte{0}); err != errShort {
			t.Errorf("oid %d wrong length should be errShort, got %v", oid, err)
		}
	}
	if _, err := DecodeBinary(OIDBool, []byte{0, 1}); err != errShort {
		t.Errorf("bool wrong length")
	}
	if _, err := DecodeBinary(OIDJSONB, nil); err != errShort {
		t.Errorf("jsonb empty")
	}
	if _, err := DecodeBinary(OIDJSONB, []byte{2, 'x'}); err == nil {
		t.Errorf("jsonb bad version")
	}
}

func TestDecodeBinaryDateTimestamp(t *testing.T) {
	be32 := func(v int32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	be64 := func(v int64) []byte {
		b := make([]byte, 8)
		u := uint64(v)
		for i := 7; i >= 0; i-- {
			b[i] = byte(u)
			u >>= 8
		}
		return b
	}
	// date: 1 day after epoch (2000-01-02)
	got, _ := DecodeBinary(OIDDate, be32(1))
	if !got.(time.Time).Equal(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("bin date: %v", got)
	}
	// timestamp: 1 second (1e6 micros) after epoch
	got, _ = DecodeBinary(OIDTimestamp, be64(1000000))
	if !got.(time.Time).Equal(time.Date(2000, 1, 1, 0, 0, 1, 0, time.UTC)) {
		t.Errorf("bin ts: %v", got)
	}
}

func TestDecodeBinaryNumeric(t *testing.T) {
	// Encode 12.34 => digits base 10000: 12, 3400; weight 0; dscale 2.
	body := []byte{
		0, 2, // ndigits
		0, 0, // weight
		0, 0, // sign +
		0, 2, // dscale
		0, 12, // digit 12
		13, 72, // 3400 = 0x0D48
	}
	got, err := DecodeBinary(OIDNumeric, body)
	if err != nil {
		t.Fatal(err)
	}
	if got.(*big.Rat).FloatString(2) != "12.34" {
		t.Errorf("bin numeric: %v", got.(*big.Rat).FloatString(2))
	}
	// negative
	body[4], body[5] = 0x40, 0x00
	got, _ = DecodeBinary(OIDNumeric, body)
	if got.(*big.Rat).FloatString(2) != "-12.34" {
		t.Errorf("bin numeric neg: %v", got)
	}
	// specials
	for sign, want := range map[uint16]string{0xC000: "NaN", 0xD000: "Infinity", 0xF000: "-Infinity"} {
		b := []byte{0, 0, 0, 0, byte(sign >> 8), byte(sign), 0, 0}
		got, _ := DecodeBinary(OIDNumeric, b)
		if got != want {
			t.Errorf("numeric special %x: %v", sign, got)
		}
	}
	// errors
	if _, err := DecodeBinary(OIDNumeric, []byte{0, 0}); err != errShort {
		t.Errorf("numeric short header")
	}
	if _, err := DecodeBinary(OIDNumeric, []byte{0, 5, 0, 0, 0, 0, 0, 0}); err != errShort {
		t.Errorf("numeric short digits")
	}
	// weight negative (fraction) exercises ratPow negative exponent
	frac := []byte{0, 1, 0xFF, 0xFF, 0, 0, 0, 4, 0, 5} // 5 * 10000^-1 = 0.0005
	got, _ = DecodeBinary(OIDNumeric, frac)
	if got.(*big.Rat).FloatString(4) != "0.0005" {
		t.Errorf("numeric frac: %v", got.(*big.Rat).FloatString(4))
	}
}

func TestDecodeBinaryArray(t *testing.T) {
	be32 := func(v int32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	// 1-dim int4 {10, NULL}
	var b []byte
	b = append(b, be32(1)...)  // ndim
	b = append(b, be32(1)...)  // has null
	b = append(b, be32(23)...) // elem oid
	b = append(b, be32(2)...)  // dim length
	b = append(b, be32(1)...)  // lower bound
	b = append(b, be32(4)...)  // len of first
	b = append(b, be32(10)...) // value 10
	b = append(b, be32(-1)...) // null
	got, err := DecodeBinary(OIDInt4Array, b)
	if err != nil || !reflect.DeepEqual(got, []any{int64(10), nil}) {
		t.Fatalf("bin array: %v %v", got, err)
	}
	// zero-dim
	z := append(append(be32(0), be32(0)...), be32(23)...)
	got, _ = DecodeBinary(OIDInt4Array, z)
	if !reflect.DeepEqual(got, []any{}) {
		t.Errorf("bin array zero-dim: %v", got)
	}
	// 2-dim {{1,2},{3,4}}
	var m []byte
	m = append(m, be32(2)...)  // ndim
	m = append(m, be32(0)...)  // has null
	m = append(m, be32(23)...) // elem
	m = append(m, be32(2)...)  // dim1 len
	m = append(m, be32(1)...)
	m = append(m, be32(2)...) // dim2 len
	m = append(m, be32(1)...)
	for _, v := range []int32{1, 2, 3, 4} {
		m = append(m, be32(4)...)
		m = append(m, be32(v)...)
	}
	got, _ = DecodeBinary(OIDInt4Array, m)
	want := []any{[]any{int64(1), int64(2)}, []any{int64(3), int64(4)}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bin 2d array: %v", got)
	}
	// errors
	if _, err := DecodeBinary(OIDInt4Array, be32(1)); err == nil {
		t.Errorf("bin array short header")
	}
	if _, err := DecodeBinary(OIDInt4Array, append(append(be32(-1), be32(0)...), be32(23)...)); err == nil {
		t.Errorf("negative ndim")
	}
	neg := append(append(append(be32(1), be32(0)...), be32(23)...), append(be32(-2), be32(1)...)...)
	if _, err := DecodeBinary(OIDInt4Array, neg); err == nil {
		t.Errorf("negative dim length")
	}
	// truncated dims
	trunc := append(append(be32(1), be32(0)...), be32(23)...)
	if _, err := DecodeBinary(OIDInt4Array, trunc); err == nil {
		t.Errorf("truncated dims")
	}
	// truncated element
	te := append(append(append(be32(1), be32(0)...), be32(23)...), append(append(be32(1), be32(1)...), be32(4)...)...)
	if _, err := DecodeBinary(OIDInt4Array, te); err == nil {
		t.Errorf("truncated element")
	}
	// element decode error
	ee := append(append(append(be32(1), be32(0)...), be32(23)...), append(append(be32(1), be32(1)...), be32(1)...)...)
	ee = append(ee, 0) // 1-byte int4 -> errShort in element
	if _, err := DecodeBinary(OIDInt4Array, ee); err == nil {
		t.Errorf("element decode error")
	}
}
