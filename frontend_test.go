package pg

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// unframe splits a framed typed message back into (type, body), verifying the
// length prefix.
func unframe(t *testing.T, b []byte) (byte, []byte) {
	t.Helper()
	if len(b) < 5 {
		t.Fatalf("message too short: %d", len(b))
	}
	length := binary.BigEndian.Uint32(b[1:5])
	if int(length) != len(b)-1 {
		t.Fatalf("length %d != body+4 %d", length, len(b)-1)
	}
	return b[0], b[5:]
}

func TestEncodeSSLAndCancel(t *testing.T) {
	ssl := EncodeSSLRequest()
	if binary.BigEndian.Uint32(ssl[4:8]) != 80877103 {
		t.Errorf("SSL magic wrong")
	}
	if binary.BigEndian.Uint32(ssl[0:4]) != 8 {
		t.Errorf("SSL length wrong")
	}
	cancel := EncodeCancelRequest(42, 99)
	if binary.BigEndian.Uint32(cancel[4:8]) != 80877102 {
		t.Errorf("cancel magic wrong")
	}
	if binary.BigEndian.Uint32(cancel[8:12]) != 42 || binary.BigEndian.Uint32(cancel[12:16]) != 99 {
		t.Errorf("cancel pid/secret wrong")
	}
}

func TestEncodePasswordAndSASL(t *testing.T) {
	tp, body := unframe(t, EncodePassword("secret"))
	if tp != 'p' || string(body) != "secret\x00" {
		t.Errorf("password: %q %q", tp, body)
	}

	tp, body = unframe(t, EncodeSASLInitialResponse("SCRAM-SHA-256", []byte("n,,n=,r=abc")))
	if tp != 'p' {
		t.Fatalf("sasl type %q", tp)
	}
	r := &readBuf{b: body}
	if r.string() != "SCRAM-SHA-256" {
		t.Errorf("mechanism wrong")
	}
	if r.int32() != int32(len("n,,n=,r=abc")) {
		t.Errorf("sasl initial length wrong")
	}

	// nil initial => -1 length.
	_, body = unframe(t, EncodeSASLInitialResponse("X", nil))
	r = &readBuf{b: body}
	r.string()
	if r.int32() != -1 {
		t.Errorf("nil initial should be -1")
	}

	tp, body = unframe(t, EncodeSASLResponse([]byte("proof")))
	if tp != 'p' || string(body) != "proof" {
		t.Errorf("sasl response wrong: %q", body)
	}
}

func TestEncodeQueryParseBind(t *testing.T) {
	tp, body := unframe(t, EncodeQuery("SELECT 1"))
	if tp != 'Q' || string(body) != "SELECT 1\x00" {
		t.Errorf("query wrong")
	}

	tp, body = unframe(t, EncodeParse("st", "SELECT $1", []uint32{23}))
	if tp != 'P' {
		t.Fatalf("parse type")
	}
	r := &readBuf{b: body}
	if r.string() != "st" || r.string() != "SELECT $1" {
		t.Errorf("parse names")
	}
	if r.int16() != 1 || r.int32() != 23 {
		t.Errorf("parse param oids")
	}

	params := []BindParam{
		{Value: []byte("42"), Format: TextFormat},
		{Value: nil, Format: TextFormat},
	}
	tp, body = unframe(t, EncodeBind("po", "st", params, []Format{TextFormat}))
	if tp != 'B' {
		t.Fatalf("bind type")
	}
	r = &readBuf{b: body}
	if r.string() != "po" || r.string() != "st" {
		t.Errorf("bind names")
	}
	if r.int16() != 2 { // param format count
		t.Errorf("bind param format count")
	}
	r.int16()
	r.int16()
	if r.int16() != 2 { // param value count
		t.Errorf("bind param value count")
	}
	if r.int32() != 2 || string(r.next(2)) != "42" {
		t.Errorf("bind first value")
	}
	if r.int32() != -1 {
		t.Errorf("bind null value")
	}
	if r.int16() != 1 || r.int16() != 0 {
		t.Errorf("bind result formats")
	}
}

func TestEncodeDescribeCloseExecuteSyncFlushTerminate(t *testing.T) {
	tp, body := unframe(t, EncodeDescribeStatement("s"))
	if tp != 'D' || body[0] != 'S' || string(body[1:]) != "s\x00" {
		t.Errorf("describe stmt wrong")
	}
	tp, body = unframe(t, EncodeDescribePortal("p"))
	if tp != 'D' || body[0] != 'P' {
		t.Errorf("describe portal wrong")
	}
	tp, body = unframe(t, EncodeCloseStatement("s"))
	if tp != 'C' || body[0] != 'S' {
		t.Errorf("close stmt wrong")
	}
	tp, body = unframe(t, EncodeClosePortal("p"))
	if tp != 'C' || body[0] != 'P' {
		t.Errorf("close portal wrong")
	}

	tp, body = unframe(t, EncodeExecute("po", 5))
	if tp != 'E' {
		t.Fatalf("execute type")
	}
	r := &readBuf{b: body}
	if r.string() != "po" || r.int32() != 5 {
		t.Errorf("execute wrong")
	}

	for _, tc := range []struct {
		b  []byte
		tp byte
	}{
		{EncodeSync(), 'S'},
		{EncodeFlush(), 'H'},
		{EncodeTerminate(), 'X'},
		{EncodeCopyDone(), 'c'},
	} {
		tp, body = unframe(t, tc.b)
		if tp != tc.tp || len(body) != 0 {
			t.Errorf("bodyless %q wrong: %q body=%q", tc.tp, tp, body)
		}
	}
}

func TestEncodeCopyDataFail(t *testing.T) {
	tp, body := unframe(t, EncodeCopyData([]byte("row\n")))
	if tp != 'd' || string(body) != "row\n" {
		t.Errorf("copydata wrong")
	}
	tp, body = unframe(t, EncodeCopyFail("nope"))
	if tp != 'f' || string(body) != "nope\x00" {
		t.Errorf("copyfail wrong")
	}
}

func TestEncodeStartupSortedKeys(t *testing.T) {
	b := EncodeStartup(StartupParams{"user": "u", "z": "1", "a": "2"})
	// After version, order must be user, a, z.
	body := b[8:] // skip len(4)+version(4)
	want := []byte("user\x00u\x00a\x002\x00z\x001\x00\x00")
	if !bytes.Equal(body, want) {
		t.Errorf("startup order:\n got %q\nwant %q", body, want)
	}
	// No user key path.
	b = EncodeStartup(StartupParams{"a": "2"})
	if !bytes.Contains(b, []byte("a\x002\x00")) {
		t.Errorf("startup without user failed")
	}
}
