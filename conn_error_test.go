package pg

import "testing"

// badFrame frames a body that is internally inconsistent (declares more content
// than it carries), so the matching Parse* returns a truncation error while
// ReadMessage itself succeeds.
func badRowDesc() []byte  { return frame('T', []byte{0, 2}) }         // says 2 fields, none follow
func badDataRow() []byte  { return frame('D', []byte{0, 1, 0, 0, 0, 9}) } // 1 col len 9, no data
func badCmd() []byte      { return frame('C', []byte("noterm")) }    // no NUL
func badError() []byte    { return frame('E', []byte("S")) }         // dangling code
func badParamDesc() []byte { return frame('t', []byte{0, 1}) }       // says 1 oid, none
func badReady() []byte    { return frame('Z', nil) }                 // no status byte

// unexpected returns a framed message of a type the given cycle does not expect.
func unexpected() []byte { return frame('K', []byte{0, 0, 0, 0, 0, 0, 0, 0}) }

func TestCollectResultErrorBranches(t *testing.T) {
	cases := map[string][]byte{
		"bad row desc":  badRowDesc(),
		"bad data row":  concat(rowDescInt4("n"), badDataRow()),
		"bad cmd":       concat(rowDescInt4("n"), badCmd()),
		"bad error":     badError(),
		"unexpected":    concat(unexpected(), unexpected()),
		"read cutoff":   rowDescInt4("n"), // stream ends, nextSignificant read fails
	}
	for name, backend := range cases {
		c := NewConn(newScript(backend))
		if _, err := c.Exec("x"); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	// EmptyQueryResponse truncation is impossible (bodyless), but the async and
	// drainToReady error paths are reachable: a bad ParameterStatus mid-stream.
	c := NewConn(newScript(frame('S', []byte("nokey"))))
	if _, err := c.Exec("x"); err == nil {
		t.Errorf("bad param status: want error")
	}
	// bad notice mid-stream
	c = NewConn(newScript(frame('N', []byte("S"))))
	if _, err := c.Exec("x"); err == nil {
		t.Errorf("bad notice: want error")
	}
	// bad notification mid-stream
	c = NewConn(newScript(frame('A', []byte{0})))
	if _, err := c.Exec("x"); err == nil {
		t.Errorf("bad notification: want error")
	}
}

func TestDrainToReadyErrorAfterResult(t *testing.T) {
	// Result then an unreadable trailer (drainToReady read error).
	backend := concat(
		rowDescInt4("n"), dataRow1("1"), frame('C', []byte("SELECT 1\x00")),
		// no ReadyForQuery: drainToReady read fails at EOF
	)
	c := NewConn(newScript(backend))
	if _, err := c.Exec("x"); err == nil {
		t.Errorf("want drainToReady error")
	}
	// Result then bad ReadyForQuery.
	backend = concat(rowDescInt4("n"), dataRow1("1"), frame('C', []byte("SELECT 1\x00")), badReady())
	c = NewConn(newScript(backend))
	if _, err := c.Exec("x"); err == nil {
		t.Errorf("want bad-ready error")
	}
}

func TestRunExtendedErrorBranches(t *testing.T) {
	cases := map[string][]byte{
		"bad param desc":     concat(frame('1', nil), badParamDesc()),
		"bad row desc":       concat(frame('1', nil), frame('2', nil), badRowDesc()),
		"bad data row":       concat(frame('1', nil), frame('2', nil), rowDescInt4("n"), badDataRow()),
		"bad cmd complete":   concat(frame('1', nil), frame('2', nil), rowDescInt4("n"), badCmd()),
		"bad error":          badError(),
		"bad ready":          concat(frame('1', nil), frame('2', nil), rowDescInt4("n"), dataRow1("1"), frame('C', []byte("S\x00")), badReady()),
		"unexpected message": concat(frame('1', nil), unexpected()),
		"read cutoff":        concat(frame('1', nil)),
	}
	for name, backend := range cases {
		c := NewConn(newScript(backend))
		if _, err := c.ExecParams("x"); err == nil {
			t.Errorf("runExtended %s: want error", name)
		}
	}
	// A result with only DataRows and no CommandComplete, terminated by
	// ReadyForQuery, yields the empty-tag fallback (result==nil path).
	backend := concat(frame('1', nil), frame('2', nil), rowDescInt4("n"), dataRow1("1"), readyForQuery('I'))
	c := NewConn(newScript(backend))
	res, err := c.ExecParams("x")
	if err != nil {
		t.Fatalf("fallback path: %v", err)
	}
	if res.Ntuples() != 1 {
		t.Errorf("fallback rows: %d", res.Ntuples())
	}
}

func TestPrepareErrorBranches(t *testing.T) {
	cases := map[string][]byte{
		"bad parse complete via unexpected": concat(unexpected()),
		"bad ready":                         concat(frame('1', nil), badReady()),
		"bad error":                         badError(),
		"read cutoff":                       concat(frame('1', nil)),
	}
	for name, backend := range cases {
		c := NewConn(newScript(backend))
		if err := c.Prepare("s", "x", nil); err == nil {
			t.Errorf("prepare %s: want error", name)
		}
	}
}

func TestStartupMoreErrorBranches(t *testing.T) {
	// bad Authentication body.
	c := NewConn(newScript(frame('R', []byte{0, 0})))
	if err := c.Startup(NewPasswordAuthenticator("u", "pw")); err == nil {
		t.Errorf("bad auth body: want error")
	}
	// bad BackendKeyData body.
	c = NewConn(newScript(frame('K', []byte{0})))
	if err := c.Startup(nil); err == nil {
		t.Errorf("bad keydata: want error")
	}
	// bad ReadyForQuery body.
	c = NewConn(newScript(concat(frame('R', []byte{0, 0, 0, 0}), badReady())))
	if err := c.Startup(nil); err == nil {
		t.Errorf("bad ready: want error")
	}
	// bad ErrorResponse body during startup.
	c = NewConn(newScript(badError()))
	if err := c.Startup(nil); err == nil {
		t.Errorf("bad error body: want error")
	}
	// Authenticator.Handle returns an error (bad MD5 salt from server).
	c = NewConn(newScript(frame('R', append([]byte{0, 0, 0, 5}, 1))))
	if err := c.Startup(NewPasswordAuthenticator("u", "pw")); err == nil {
		t.Errorf("auth handle error: want error")
	}
}
