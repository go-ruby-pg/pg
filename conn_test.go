package pg

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// scriptRW is a ReadWriter whose reads come from a pre-scripted backend byte
// stream and whose writes are captured. It models the host transport seam.
type scriptRW struct {
	in  *bytes.Reader // backend -> client
	out bytes.Buffer  // client -> backend (captured)
}

func newScript(backend []byte) *scriptRW {
	return &scriptRW{in: bytes.NewReader(backend)}
}

func (s *scriptRW) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *scriptRW) Write(p []byte) (int, error) { return s.out.Write(p) }

// concat joins framed backend messages into one stream.
func concat(msgs ...[]byte) []byte {
	var b []byte
	for _, m := range msgs {
		b = append(b, m...)
	}
	return b
}

// rowDesc builds a framed RowDescription for the given single int4 column "n".
func rowDescInt4(name string) []byte {
	var w writeBuf
	w.int16(1)
	w.string(name)
	w.int32(0)
	w.int16(0)
	w.int32(int32(OIDInt4))
	w.int16(4)
	w.int32(-1)
	w.int16(0)
	return frame('T', w.b)
}

func dataRow1(val string) []byte {
	var w writeBuf
	w.int16(1)
	w.int32(int32(len(val)))
	w.bytes([]byte(val))
	return frame('D', w.b)
}

func readyForQuery(st byte) []byte { return frame('Z', []byte{st}) }

func TestConnExec(t *testing.T) {
	backend := concat(
		rowDescInt4("n"),
		dataRow1("1"),
		dataRow1("2"),
		frame('C', []byte("SELECT 2\x00")),
		readyForQuery('I'),
	)
	s := newScript(backend)
	c := NewConn(s)
	res, err := c.Exec("SELECT n FROM t")
	if err != nil {
		t.Fatal(err)
	}
	if res.Ntuples() != 2 {
		t.Errorf("ntuples %d", res.Ntuples())
	}
	if c.TransactionStatus() != TxnIdle {
		t.Errorf("txn status")
	}
	// The query bytes were written.
	if !bytes.Contains(s.out.Bytes(), []byte("SELECT n FROM t")) {
		t.Errorf("query not written")
	}
}

func TestConnExecEmptyQuery(t *testing.T) {
	backend := concat(frame('I', nil), readyForQuery('I'))
	c := NewConn(newScript(backend))
	res, err := c.Exec("")
	if err != nil || res.Ntuples() != 0 {
		t.Fatalf("empty query: %v", err)
	}
}

func TestConnExecError(t *testing.T) {
	backend := concat(
		frame('E', []byte("SERROR\x00C42P01\x00Mno table\x00\x00")),
		readyForQuery('E'),
	)
	c := NewConn(newScript(backend))
	_, err := c.Exec("SELECT bad")
	if err == nil {
		t.Fatal("want error")
	}
	var pgErr *Error
	if !errors.As(err, &pgErr) || pgErr.SQLState() != "42P01" {
		t.Errorf("wrong error: %v", err)
	}
	if c.TransactionStatus() != TxnError {
		t.Errorf("txn error status")
	}
}

func TestConnAsyncCapture(t *testing.T) {
	var notices int
	var notifs int
	backend := concat(
		frame('S', []byte("client_encoding\x00UTF8\x00")),
		frame('N', []byte("SWARNING\x00Mheads up\x00\x00")),
		frame('A', []byte{0, 0, 0, 1, 'c', 'h', 0, 'p', 0}),
		rowDescInt4("n"),
		dataRow1("7"),
		frame('C', []byte("SELECT 1\x00")),
		readyForQuery('I'),
	)
	c := NewConn(newScript(backend))
	c.OnNotice(func(*ErrorFields) { notices++ })
	c.OnNotification(func(*NotificationResponse) { notifs++ })
	res, err := c.Exec("SELECT n")
	if err != nil {
		t.Fatal(err)
	}
	if res.Ntuples() != 1 {
		t.Errorf("rows")
	}
	if notices != 1 || notifs != 1 {
		t.Errorf("async callbacks: notices=%d notifs=%d", notices, notifs)
	}
	if v, ok := c.Parameter("client_encoding"); !ok || v != "UTF8" {
		t.Errorf("param capture")
	}
}

func TestConnExecParams(t *testing.T) {
	backend := concat(
		frame('1', nil), // ParseComplete
		frame('2', nil), // BindComplete
		rowDescInt4("n"),
		dataRow1("9"),
		frame('C', []byte("SELECT 1\x00")),
		readyForQuery('I'),
	)
	s := newScript(backend)
	c := NewConn(s)
	res, err := c.ExecParams("SELECT $1::int", int64(9))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := res.Getvalue(0, 0); v != int64(9) {
		t.Errorf("value: %v", v)
	}
	// Parse and Bind were sent.
	if !bytes.Contains(s.out.Bytes(), []byte("SELECT $1::int")) {
		t.Errorf("parse not written")
	}
}

func TestConnExecParamsNoData(t *testing.T) {
	// A statement with no result columns: ParseComplete, BindComplete, NoData,
	// ParameterDescription, PortalSuspended, then CommandComplete.
	backend := concat(
		frame('1', nil),
		frame('2', nil),
		frame('t', []byte{0, 1, 0, 0, 0, 23}), // ParameterDescription
		frame('n', nil),                       // NoData
		frame('s', nil),                       // PortalSuspended
		frame('C', []byte("UPDATE 1\x00")),
		readyForQuery('T'),
	)
	c := NewConn(newScript(backend))
	res, err := c.ExecParams("UPDATE t SET x=1")
	if err != nil {
		t.Fatal(err)
	}
	if res.CmdTuples() != 1 {
		t.Errorf("cmd tuples")
	}
}

func TestConnExecParamsEmptyQuery(t *testing.T) {
	backend := concat(frame('1', nil), frame('2', nil), frame('I', nil), readyForQuery('I'))
	c := NewConn(newScript(backend))
	res, err := c.ExecParams("")
	if err != nil || res.Ntuples() != 0 {
		t.Fatalf("empty extended: %v", err)
	}
}

func TestConnExecParamsError(t *testing.T) {
	backend := concat(
		frame('E', []byte("SERROR\x00Mbad param\x00\x00")),
		readyForQuery('I'),
	)
	c := NewConn(newScript(backend))
	if _, err := c.ExecParams("SELECT $1", int64(1)); err == nil {
		t.Errorf("want extended error")
	}
	// Encode error before any write.
	if _, err := c.ExecParams("x", unencodable{}); err == nil {
		t.Errorf("want encode error")
	}
}

func TestConnPrepareExecPrepared(t *testing.T) {
	backend := concat(
		frame('1', nil),    // ParseComplete (prepare)
		readyForQuery('I'), // after Sync
		frame('2', nil),    // BindComplete (exec_prepared)
		rowDescInt4("n"),
		dataRow1("5"),
		frame('C', []byte("SELECT 1\x00")),
		readyForQuery('I'),
	)
	c := NewConn(newScript(backend))
	if err := c.Prepare("st", "SELECT $1::int", []uint32{23}); err != nil {
		t.Fatal(err)
	}
	res, err := c.ExecPrepared("st", int64(5))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := res.Getvalue(0, 0); v != int64(5) {
		t.Errorf("prepared value: %v", v)
	}
}

func TestConnPrepareError(t *testing.T) {
	backend := concat(frame('E', []byte("SERROR\x00Msyntax\x00\x00")), readyForQuery('I'))
	c := NewConn(newScript(backend))
	if err := c.Prepare("st", "BAD", nil); err == nil {
		t.Errorf("want prepare error")
	}
	// encode error in exec_prepared
	if _, err := c.ExecPrepared("st", unencodable{}); err == nil {
		t.Errorf("want encode error")
	}
}

func TestConnMisc(t *testing.T) {
	c := NewConn(newScript(nil))
	if c.EscapeString("a'b") != "a''b" ||
		c.EscapeLiteral("x") != "'x'" ||
		c.EscapeIdentifier("i") != `"i"` ||
		c.QuoteIdent("q") != `"q"` {
		t.Errorf("escape method forms")
	}
	if err := c.Terminate(); err != nil {
		t.Errorf("terminate: %v", err)
	}
	if _, ok := c.BackendKey(); ok {
		t.Errorf("no backend key yet")
	}
	if _, err := c.CancelRequest(); err == nil {
		t.Errorf("cancel without key should error")
	}
}

// errRW returns an error on Write, to exercise write-error paths.
type errRW struct{ readErr, writeErr bool }

func (e *errRW) Read(p []byte) (int, error) {
	if e.readErr {
		return 0, io.ErrClosedPipe
	}
	return 0, io.EOF
}
func (e *errRW) Write(p []byte) (int, error) {
	if e.writeErr {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestConnWriteReadErrors(t *testing.T) {
	// Write error on Exec.
	c := NewConn(&errRW{writeErr: true})
	if _, err := c.Exec("x"); err == nil {
		t.Errorf("want write error")
	}
	// Read error (EOF) collecting result.
	c = NewConn(&errRW{})
	if _, err := c.Exec("x"); err == nil {
		t.Errorf("want read error")
	}
	// ExecParams write error.
	c = NewConn(&errRW{writeErr: true})
	if _, err := c.ExecParams("x"); err == nil {
		t.Errorf("want extended write error")
	}
	// Prepare write error.
	c = NewConn(&errRW{writeErr: true})
	if err := c.Prepare("s", "x", nil); err == nil {
		t.Errorf("want prepare write error")
	}
	// ExecPrepared write error.
	c = NewConn(&errRW{writeErr: true})
	if _, err := c.ExecPrepared("s"); err == nil {
		t.Errorf("want execprepared write error")
	}
}
