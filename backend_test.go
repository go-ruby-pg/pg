package pg

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

// frame builds a framed backend message from a type byte and body, for feeding
// ReadMessage / Parse*.
func frame(tp byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = tp
	n := uint32(4 + len(body))
	out[1] = byte(n >> 24)
	out[2] = byte(n >> 16)
	out[3] = byte(n >> 8)
	out[4] = byte(n)
	copy(out[5:], body)
	return out
}

func mustMsg(tp byte, body []byte) Message { return Message{Type: tp, Body: body} }

func TestReadMessage(t *testing.T) {
	buf := bytes.NewReader(frame('Z', []byte{'I'}))
	m, err := ReadMessage(buf)
	if err != nil || m.Type != 'Z' || !bytes.Equal(m.Body, []byte{'I'}) {
		t.Fatalf("read: %v %+v", err, m)
	}
	// Clean EOF.
	if _, err := ReadMessage(buf); err != io.EOF {
		t.Errorf("want EOF got %v", err)
	}
	// Truncated header.
	if _, err := ReadMessage(bytes.NewReader([]byte{'Z', 0, 0})); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated header: %v", err)
	}
	// Truncated body: header declares one body byte but none follow.
	if _, err := ReadMessage(bytes.NewReader(frame('Z', []byte{'I'})[:5])); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated body: %v", err)
	}
	// Invalid length (< 4).
	bad := []byte{'Z', 0, 0, 0, 2, 0}
	if _, err := ReadMessage(bytes.NewReader(bad)); err == nil {
		t.Errorf("want invalid-length error")
	}
}

func TestParseAuthentication(t *testing.T) {
	i32 := func(v int32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	// OK
	a, err := ParseAuthentication(mustMsg('R', i32(0)))
	if err != nil || a.Kind != AuthOK {
		t.Fatalf("authOK: %v %+v", err, a)
	}
	// MD5 + salt
	a, err = ParseAuthentication(mustMsg('R', append(i32(5), 1, 2, 3, 4)))
	if err != nil || a.Kind != AuthMD5Password || !bytes.Equal(a.Salt, []byte{1, 2, 3, 4}) {
		t.Fatalf("md5: %v %+v", err, a)
	}
	// SASL mechanisms
	body := append(i32(10), []byte("SCRAM-SHA-256\x00SCRAM-SHA-256-PLUS\x00\x00")...)
	a, err = ParseAuthentication(mustMsg('R', body))
	if err != nil || len(a.Mechanisms) != 2 {
		t.Fatalf("sasl: %v %+v", err, a)
	}
	// SASLContinue data
	a, err = ParseAuthentication(mustMsg('R', append(i32(11), []byte("r=xyz")...)))
	if err != nil || string(a.Data) != "r=xyz" {
		t.Fatalf("saslcontinue: %v %+v", err, a)
	}
	// SASLFinal
	a, _ = ParseAuthentication(mustMsg('R', append(i32(12), []byte("v=sig")...)))
	if a.Kind != AuthSASLFinal || string(a.Data) != "v=sig" {
		t.Errorf("saslfinal wrong")
	}
	// Wrong type
	if _, err := ParseAuthentication(mustMsg('X', nil)); err != errBadType {
		t.Errorf("bad type: %v", err)
	}
	// Truncated
	if _, err := ParseAuthentication(mustMsg('R', []byte{0, 0})); err == nil {
		t.Errorf("want truncation error")
	}
}

func TestParseStatusKeyReady(t *testing.T) {
	ps, err := ParseParameterStatus(mustMsg('S', []byte("client_encoding\x00UTF8\x00")))
	if err != nil || ps.Name != "client_encoding" || ps.Value != "UTF8" {
		t.Fatalf("paramstatus: %v %+v", err, ps)
	}
	if _, err := ParseParameterStatus(mustMsg('X', nil)); err != errBadType {
		t.Errorf("ps bad type")
	}
	if _, err := ParseParameterStatus(mustMsg('S', []byte("nokey"))); err == nil {
		t.Errorf("ps truncation")
	}

	k, err := ParseBackendKeyData(mustMsg('K', []byte{0, 0, 0, 7, 0, 0, 0, 9}))
	if err != nil || k.ProcessID != 7 || k.SecretKey != 9 {
		t.Fatalf("keydata: %v %+v", err, k)
	}
	if _, err := ParseBackendKeyData(mustMsg('X', nil)); err != errBadType {
		t.Errorf("kd bad type")
	}
	if _, err := ParseBackendKeyData(mustMsg('K', []byte{0})); err == nil {
		t.Errorf("kd truncation")
	}

	st, err := ParseReadyForQuery(mustMsg('Z', []byte{'T'}))
	if err != nil || st != TxnActive {
		t.Fatalf("rfq: %v %v", err, st)
	}
	if _, err := ParseReadyForQuery(mustMsg('X', nil)); err != errBadType {
		t.Errorf("rfq bad type")
	}
	if _, err := ParseReadyForQuery(mustMsg('Z', nil)); err == nil {
		t.Errorf("rfq truncation")
	}
}

func TestParseRowDescriptionAndDataRow(t *testing.T) {
	var w writeBuf
	w.int16(2)
	w.string("id")
	w.int32(100) // table oid
	w.int16(1)   // attr
	w.int32(23)  // int4
	w.int16(4)   // size
	w.int32(-1)  // typmod
	w.int16(0)   // text format
	w.string("name")
	w.int32(0)
	w.int16(0)
	w.int32(25)
	w.int16(-1)
	w.int32(-1)
	w.int16(0)
	rd, err := ParseRowDescription(mustMsg('T', w.b))
	if err != nil || len(rd.Fields) != 2 || rd.Fields[0].Name != "id" || rd.Fields[1].DataTypeOID != 25 {
		t.Fatalf("rowdesc: %v %+v", err, rd)
	}
	if _, err := ParseRowDescription(mustMsg('X', nil)); err != errBadType {
		t.Errorf("rd bad type")
	}
	if _, err := ParseRowDescription(mustMsg('T', []byte{0, 1})); err == nil {
		t.Errorf("rd truncation")
	}

	var d writeBuf
	d.int16(2)
	d.int32(2)
	d.bytes([]byte("42"))
	d.int32(-1) // null
	dr, err := ParseDataRow(mustMsg('D', d.b))
	if err != nil || len(dr.Values) != 2 || string(dr.Values[0]) != "42" || dr.Values[1] != nil {
		t.Fatalf("datarow: %v %+v", err, dr)
	}
	if _, err := ParseDataRow(mustMsg('X', nil)); err != errBadType {
		t.Errorf("dr bad type")
	}
	if _, err := ParseDataRow(mustMsg('D', []byte{0, 1, 0, 0, 0, 5})); err == nil {
		t.Errorf("dr truncation")
	}
}

func TestParseCommandCompleteNotification(t *testing.T) {
	tag, err := ParseCommandComplete(mustMsg('C', []byte("SELECT 3\x00")))
	if err != nil || tag != "SELECT 3" {
		t.Fatalf("cc: %v %q", err, tag)
	}
	if _, err := ParseCommandComplete(mustMsg('X', nil)); err != errBadType {
		t.Errorf("cc bad type")
	}
	if _, err := ParseCommandComplete(mustMsg('C', []byte("noterm"))); err == nil {
		t.Errorf("cc truncation")
	}

	nr, err := ParseNotificationResponse(mustMsg('A', []byte{0, 0, 0, 5, 'c', 'h', 0, 'p', 'l', 0}))
	if err != nil || nr.ProcessID != 5 || nr.Channel != "ch" || nr.Payload != "pl" {
		t.Fatalf("notify: %v %+v", err, nr)
	}
	if _, err := ParseNotificationResponse(mustMsg('X', nil)); err != errBadType {
		t.Errorf("notify bad type")
	}
	if _, err := ParseNotificationResponse(mustMsg('A', []byte{0})); err == nil {
		t.Errorf("notify truncation")
	}
}

func TestParseParameterDescription(t *testing.T) {
	pd, err := ParseParameterDescription(mustMsg('t', []byte{0, 2, 0, 0, 0, 23, 0, 0, 0, 25}))
	if err != nil || !reflect.DeepEqual(pd.ParamOIDs, []uint32{23, 25}) {
		t.Fatalf("paramdesc: %v %+v", err, pd)
	}
	if _, err := ParseParameterDescription(mustMsg('X', nil)); err != errBadType {
		t.Errorf("pd bad type")
	}
	if _, err := ParseParameterDescription(mustMsg('t', []byte{0, 1})); err == nil {
		t.Errorf("pd truncation")
	}
}

func TestParseCopyResponses(t *testing.T) {
	c, err := ParseCopyResponse(mustMsg('G', []byte{1, 0, 2, 0, 1, 0, 1}))
	if err != nil || c.OverallFormat != 1 || len(c.ColumnFormats) != 2 || c.ColumnFormats[0] != BinaryFormat {
		t.Fatalf("copyin: %v %+v", err, c)
	}
	if _, err := ParseCopyResponse(mustMsg('H', []byte{0, 0, 0})); err != nil {
		t.Errorf("copyout: %v", err)
	}
	if _, err := ParseCopyResponse(mustMsg('W', []byte{0, 0, 0})); err != nil {
		t.Errorf("copyboth: %v", err)
	}
	if _, err := ParseCopyResponse(mustMsg('X', nil)); err != errBadType {
		t.Errorf("copy bad type")
	}
	if _, err := ParseCopyResponse(mustMsg('G', []byte{1, 0})); err == nil {
		t.Errorf("copy truncation")
	}

	data, err := ParseCopyData(mustMsg('d', []byte("row")))
	if err != nil || string(data) != "row" {
		t.Fatalf("copydata: %v %q", err, data)
	}
	if _, err := ParseCopyData(mustMsg('X', nil)); err != errBadType {
		t.Errorf("copydata bad type")
	}
}

func TestParseEmptyMessages(t *testing.T) {
	checks := []struct {
		fn func(Message) error
		tp byte
	}{
		{ParseBindComplete, '2'},
		{ParseParseComplete, '1'},
		{ParseCloseComplete, '3'},
		{ParseNoData, 'n'},
		{ParseEmptyQueryResponse, 'I'},
		{ParsePortalSuspended, 's'},
		{ParseCopyDone, 'c'},
	}
	for _, c := range checks {
		if err := c.fn(mustMsg(c.tp, nil)); err != nil {
			t.Errorf("%q: %v", c.tp, err)
		}
		if err := c.fn(mustMsg('Z', nil)); err != errBadType {
			t.Errorf("%q bad type: %v", c.tp, err)
		}
	}
}
