package pg

import (
	"errors"
	"math/big"
	"reflect"
	"testing"
)

// numBin builds a binary numeric value (ndigits/weight/sign/dscale + base-10000
// digits) for exercising decodeNumericBin/ratPow.
func numBin(weight int16, sign uint16, digits ...uint16) []byte {
	b := []byte{
		byte(len(digits) >> 8), byte(len(digits)),
		byte(uint16(weight) >> 8), byte(uint16(weight)),
		byte(sign >> 8), byte(sign),
		0, 0, // dscale
	}
	for _, d := range digits {
		b = append(b, byte(d>>8), byte(d))
	}
	return b
}

// TestRatPowPositiveExp drives ratPow through weight>0 (positive exponent, the
// SetInt branch) via a binary numeric of value 10000 (digit 1 at weight 1).
func TestRatPowPositiveExp(t *testing.T) {
	got, err := DecodeBinary(OIDNumeric, numBin(1, numericPos, 1))
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Rat).SetInt64(10000)
	if r, ok := got.(*big.Rat); !ok || r.Cmp(want) != 0 {
		t.Errorf("numeric 10000 = %v, want %v", got, want)
	}
	// ratPow directly, positive and zero exponents.
	if ratPow(big.NewInt(10), 2).Cmp(big.NewRat(100, 1)) != 0 {
		t.Errorf("ratPow(10,2)")
	}
	if ratPow(big.NewInt(10), 0).Cmp(big.NewRat(1, 1)) != 0 {
		t.Errorf("ratPow(10,0)")
	}
}

// TestFromHexUppercase covers the A-F branch of fromHex through a hex bytea.
func TestFromHexUppercase(t *testing.T) {
	got, err := DecodeText(OIDBytea, []byte(`\xDEadBE`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []byte{0xDE, 0xAD, 0xBE}) {
		t.Errorf("bytea uppercase hex = % x", got)
	}
}

// TestArrayParserBranches covers skipSpace, unterminated, and unexpected-char.
func TestArrayParserBranches(t *testing.T) {
	// Leading/internal spaces exercise the skipSpace loop body.
	got, err := DecodeText(OIDInt4Array, []byte("{ 1 , 2 }"))
	if err != nil {
		t.Fatalf("spaced array: %v", err)
	}
	if !reflect.DeepEqual(got, []any{int64(1), int64(2)}) {
		t.Errorf("spaced array = %v", got)
	}

	// Unterminated after a delimiter -> "unterminated array".
	if _, err := DecodeText(OIDInt4Array, []byte("{1,")); err == nil {
		t.Errorf("want unterminated array error")
	}
	// Empty-but-open brace with only spaces (loop hits end).
	if _, err := DecodeText(OIDInt4Array, []byte("{  ")); err == nil {
		t.Errorf("want unterminated array error (spaces)")
	}
	// Unexpected char after a quoted scalar -> default branch (an unquoted
	// scalar would swallow the separator, so use a quoted element).
	if _, err := DecodeText(OIDTextArray, []byte(`{"a"x}`)); err == nil {
		t.Errorf("want unexpected char error")
	}
}

// TestRatScaleTerminating covers the /2 branch of ratScale via 0.5 = 1/2.
func TestRatScaleTerminating(t *testing.T) {
	half := big.NewRat(1, 2)
	out, err := EncodeParam(half)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "0.5" {
		t.Errorf("EncodeParam(1/2) = %q, want 0.5", out)
	}
	// A /5 terminating value and a non-terminating (1/3) for the other arms.
	if out, _ := EncodeParam(big.NewRat(1, 5)); string(out) != "0.2" {
		t.Errorf("EncodeParam(1/5) = %q", out)
	}
	if out, _ := EncodeParam(big.NewRat(1, 3)); len(out) < 5 {
		t.Errorf("EncodeParam(1/3) = %q, want wide precision", out)
	}
}

// TestParseSCRAMEmptyPart covers the empty-part continue in parseSCRAM via a
// trailing comma.
func TestParseSCRAMEmptyPart(t *testing.T) {
	m, err := parseSCRAM("r=abc,s=def,")
	if err != nil {
		t.Fatal(err)
	}
	if m["r"] != "abc" || m["s"] != "def" {
		t.Errorf("parseSCRAM = %v", m)
	}
}

// TestParseFieldsTruncated covers the r.fail() after reading the field code in
// parseFields (an error field stream with no terminating NUL byte).
func TestParseFieldsTruncated(t *testing.T) {
	// Body ends immediately -> first r.byte() fails.
	if _, err := parseFields(nil); err == nil {
		t.Errorf("want truncated parseFields error (empty)")
	}
	// A field code with an unterminated value, then EOF before the next code.
	if _, err := parseFields([]byte("Sfatal")); err == nil {
		t.Errorf("want truncated parseFields error (no NUL)")
	}
}

// errAuth is an Authenticator whose Handle always fails, to cover the
// auth.Handle error branch in Conn.Startup.
type errAuth struct{}

func (errAuth) Handle(*Conn, *Authentication) error { return errors.New("auth boom") }

func TestStartupAuthHandleError(t *testing.T) {
	// Server requests cleartext auth (kind 3); our authenticator errors.
	c := NewConn(newScript(auth(3, nil)))
	if err := c.Startup(errAuth{}); err == nil {
		t.Errorf("want auth.Handle error")
	}
}
