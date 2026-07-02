package pg

import (
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestEncodeParamScalars(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{true, "t"},
		{false, "f"},
		{int(5), "5"},
		{int8(-1), "-1"},
		{int16(-2), "-2"},
		{int32(-3), "-3"},
		{int64(-4), "-4"},
		{uint(1), "1"},
		{uint8(2), "2"},
		{uint16(3), "3"},
		{uint32(4), "4"},
		{uint64(5), "5"},
		{big.NewInt(123), "123"},
		{float32(1.5), "1.5"},
		{float64(2.25), "2.25"},
		{"hi", "hi"},
	}
	for _, c := range cases {
		got, err := EncodeParam(c.in)
		if err != nil {
			t.Errorf("EncodeParam(%v) err %v", c.in, err)
			continue
		}
		if c.in == nil {
			if got != nil {
				t.Errorf("nil should encode to nil, got %q", got)
			}
			continue
		}
		if string(got) != c.want {
			t.Errorf("EncodeParam(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestEncodeParamFloatSpecials(t *testing.T) {
	for in, want := range map[float64]string{
		math.NaN():   "NaN",
		math.Inf(1):  "Infinity",
		math.Inf(-1): "-Infinity",
	} {
		got, _ := EncodeParam(in)
		if string(got) != want {
			t.Errorf("float %v => %q want %q", in, got, want)
		}
	}
}

func TestEncodeParamRat(t *testing.T) {
	// terminating decimal
	got, _ := EncodeParam(big.NewRat(1, 4))
	if string(got) != "0.25" {
		t.Errorf("rat 1/4: %q", got)
	}
	// integer rat
	got, _ = EncodeParam(big.NewRat(5, 1))
	if string(got) != "5" {
		t.Errorf("rat 5/1: %q", got)
	}
	// non-terminating -> 30 places
	got, _ = EncodeParam(big.NewRat(1, 3))
	if len(got) < 5 || string(got[:4]) != "0.33" {
		t.Errorf("rat 1/3: %q", got)
	}
}

func TestEncodeParamByteaAndTime(t *testing.T) {
	got, _ := EncodeParam([]byte{0x0a, 0xff})
	if string(got) != `\x0aff` {
		t.Errorf("bytea: %q", got)
	}
	tm := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	got, _ = EncodeParam(tm)
	if string(got) != "2026-07-01 12:00:00+00:00" {
		t.Errorf("time: %q", got)
	}
}

func TestEncodeParamArray(t *testing.T) {
	got, err := EncodeParam([]any{int64(1), int64(2)})
	if err != nil || string(got) != "{1,2}" {
		t.Errorf("int array: %q %v", got, err)
	}
	got, _ = EncodeParam([]any{"a", nil, "b,c", ""})
	if string(got) != `{a,NULL,"b,c",""}` {
		t.Errorf("mixed array: %q", got)
	}
	got, _ = EncodeParam([]any{[]any{int64(1)}, []any{int64(2)}})
	if string(got) != "{{1},{2}}" {
		t.Errorf("nested array: %q", got)
	}
	// quoting of NULL literal string and backslash/quote
	got, _ = EncodeParam([]any{"NULL", `x"y\z`})
	if string(got) != `{"NULL","x\"y\\z"}` {
		t.Errorf("quoting: %q", got)
	}
}

type unencodable struct{}

func TestEncodeParamErrors(t *testing.T) {
	if _, err := EncodeParam(unencodable{}); err == nil {
		t.Errorf("want unencodable error")
	}
	// error propagation through arrays
	if _, err := EncodeParam([]any{unencodable{}}); err == nil {
		t.Errorf("want array element error")
	}
	if _, err := EncodeParam([]any{[]any{unencodable{}}}); err == nil {
		t.Errorf("want nested array element error")
	}
}

func TestRoundTripEncodeDecodeArray(t *testing.T) {
	// Encode an array literal then decode it back.
	enc, _ := EncodeParam([]any{int64(1), int64(2), int64(3)})
	dec, err := DecodeText(OIDInt4Array, enc)
	if err != nil || !reflect.DeepEqual(dec, []any{int64(1), int64(2), int64(3)}) {
		t.Errorf("roundtrip: %v %v", dec, err)
	}
}

func TestEscapeFunctions(t *testing.T) {
	if EscapeString("a'b") != "a''b" {
		t.Errorf("escape_string")
	}
	if EscapeLiteral("a'b") != "'a''b'" {
		t.Errorf("escape_literal simple: %q", EscapeLiteral("a'b"))
	}
	if EscapeLiteral(`a\b`) != ` E'a\\b'` {
		t.Errorf("escape_literal backslash: %q", EscapeLiteral(`a\b`))
	}
	if EscapeIdentifier(`a"b`) != `"a""b"` {
		t.Errorf("escape_identifier: %q", EscapeIdentifier(`a"b`))
	}
	if QuoteIdent("tbl") != `"tbl"` {
		t.Errorf("quote_ident simple: %q", QuoteIdent("tbl"))
	}
	if QuoteIdent("s.t") != `"s"."t"` {
		t.Errorf("quote_ident dotted: %q", QuoteIdent("s.t"))
	}
}
