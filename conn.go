package pg

import (
	"errors"
	"fmt"
	"io"
)

// Conn is the PG::Connection-like surface, driving the v3 protocol over an
// injected transport. The socket is a *host seam*: Conn never dials — the host
// supplies an already-connected (and, if needed, TLS-wrapped and authenticated)
// io.ReadWriter as RW. This mirrors the go-ruby net-* libraries, keeping the
// codec fully testable against in-memory pipes and canned byte streams.
type Conn struct {
	// RW is the transport the protocol runs over. Required.
	RW io.ReadWriter
	// notices, if set, receives every NoticeResponse the server interleaves.
	notices func(*ErrorFields)
	// notifications, if set, receives every NotificationResponse (LISTEN/NOTIFY).
	notifications func(*NotificationResponse)
	// params captures ParameterStatus updates (server_version, client_encoding…).
	params map[string]string
	// key is the most recent BackendKeyData, for building a CancelRequest.
	key *BackendKeyData
	// txStatus is the transaction status from the last ReadyForQuery.
	txStatus TransactionStatus
}

// NewConn wraps a transport as a Conn.
func NewConn(rw io.ReadWriter) *Conn {
	return &Conn{RW: rw, params: map[string]string{}}
}

// OnNotice registers a callback for NoticeResponse messages.
func (c *Conn) OnNotice(fn func(*ErrorFields)) { c.notices = fn }

// OnNotification registers a callback for NotificationResponse messages.
func (c *Conn) OnNotification(fn func(*NotificationResponse)) { c.notifications = fn }

// Parameter returns a server ParameterStatus value captured during the session.
func (c *Conn) Parameter(name string) (string, bool) {
	v, ok := c.params[name]
	return v, ok
}

// BackendKey returns the connection's cancellation key, if BackendKeyData was
// seen.
func (c *Conn) BackendKey() (*BackendKeyData, bool) { return c.key, c.key != nil }

// TransactionStatus returns the status from the last ReadyForQuery.
func (c *Conn) TransactionStatus() TransactionStatus { return c.txStatus }

// write sends one framed frontend message.
func (c *Conn) write(b []byte) error {
	_, err := c.RW.Write(b)
	return err
}

// read reads one framed backend message.
func (c *Conn) read() (Message, error) { return ReadMessage(c.RW) }

// handleAsync consumes a NoticeResponse / NotificationResponse / ParameterStatus
// message, dispatching to callbacks, and reports whether it did so. Other
// messages fall through.
func (c *Conn) handleAsync(m Message) (bool, error) {
	switch m.Type {
	case msgNoticeResponse:
		ef, err := ParseNoticeResponse(m)
		if err != nil {
			return true, err
		}
		if c.notices != nil {
			c.notices(ef)
		}
		return true, nil
	case msgNotification:
		nr, err := ParseNotificationResponse(m)
		if err != nil {
			return true, err
		}
		if c.notifications != nil {
			c.notifications(nr)
		}
		return true, nil
	case msgParameterStatus:
		ps, err := ParseParameterStatus(m)
		if err != nil {
			return true, err
		}
		c.params[ps.Name] = ps.Value
		return true, nil
	}
	return false, nil
}

// nextSignificant reads messages, transparently consuming async ones, until a
// non-async message arrives.
func (c *Conn) nextSignificant() (Message, error) {
	for {
		m, err := c.read()
		if err != nil {
			return Message{}, err
		}
		handled, herr := c.handleAsync(m)
		if herr != nil {
			return Message{}, herr
		}
		if !handled {
			return m, nil
		}
	}
}

// collectResult reads the message stream after a query has been sent, up to and
// including CommandComplete / EmptyQueryResponse, assembling a Result. It
// updates txStatus from any ReadyForQuery it encounters (simple query) but does
// not require one (the extended path sends its own Sync). An ErrorResponse is
// returned as an *Error.
func (c *Conn) collectResult() (*Result, error) {
	var desc *RowDescription
	var rows []*DataRow
	for {
		m, err := c.nextSignificant()
		if err != nil {
			return nil, err
		}
		switch m.Type {
		case msgRowDescription:
			desc, err = ParseRowDescription(m)
			if err != nil {
				return nil, err
			}
		case msgDataRow:
			dr, err := ParseDataRow(m)
			if err != nil {
				return nil, err
			}
			rows = append(rows, dr)
		case msgCommandComplete:
			tag, err := ParseCommandComplete(m)
			if err != nil {
				return nil, err
			}
			return NewResult(desc, rows, tag)
		case msgEmptyQuery:
			// EmptyQueryResponse is bodyless; its type already matched.
			return NewResult(desc, rows, "")
		case msgErrorResponse:
			ef, err := ParseErrorResponse(m)
			if err != nil {
				return nil, err
			}
			return nil, ef.AsError()
		default:
			return nil, fmt.Errorf("pg: unexpected message %q collecting result", m.Type)
		}
	}
}

// drainToReady reads messages until ReadyForQuery, updating txStatus. It is used
// to resynchronise after a command so the connection is ready for the next.
func (c *Conn) drainToReady() error {
	for {
		m, err := c.nextSignificant()
		if err != nil {
			return err
		}
		if m.Type == msgReadyForQuery {
			st, err := ParseReadyForQuery(m)
			if err != nil {
				return err
			}
			c.txStatus = st
			return nil
		}
	}
}

// Exec runs a simple query and returns its Result, then resynchronises to
// ReadyForQuery (PG::Connection#exec / #query). Only the first result of a
// multi-statement string is returned; the rest are drained.
func (c *Conn) Exec(sql string) (*Result, error) {
	if err := c.write(EncodeQuery(sql)); err != nil {
		return nil, err
	}
	res, err := c.collectResult()
	if err != nil {
		// Still resynchronise so the connection stays usable.
		_ = c.drainToReady()
		return nil, err
	}
	if err := c.drainToReady(); err != nil {
		return nil, err
	}
	return res, nil
}

// ExecParams runs a one-shot parameterised query over the extended protocol
// (Parse/Bind/Describe/Execute/Sync on the unnamed statement + portal),
// requesting text results (PG::Connection#exec_params). Parameters are encoded
// with EncodeParam.
func (c *Conn) ExecParams(sql string, args ...any) (*Result, error) {
	params, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	msgs := [][]byte{
		EncodeParse("", sql, nil),
		EncodeBind("", "", params, nil),
		EncodeDescribePortal(""),
		EncodeExecute("", 0),
		EncodeSync(),
	}
	return c.runExtended(msgs)
}

// Prepare issues a Parse for a named statement and waits for ParseComplete
// (PG::Connection#prepare). paramOIDs may pin parameter types (nil to infer).
func (c *Conn) Prepare(name, sql string, paramOIDs []uint32) error {
	msgs := [][]byte{EncodeParse(name, sql, paramOIDs), EncodeSync()}
	if err := c.writeAll(msgs); err != nil {
		return err
	}
	for {
		m, err := c.nextSignificant()
		if err != nil {
			return err
		}
		switch m.Type {
		case msgParseComplete:
			// ParseComplete is bodyless; its type already matched.
		case msgReadyForQuery:
			st, err := ParseReadyForQuery(m)
			if err != nil {
				return err
			}
			c.txStatus = st
			return nil
		case msgErrorResponse:
			ef, err := ParseErrorResponse(m)
			if err != nil {
				return err
			}
			_ = c.drainToReady()
			return ef.AsError()
		default:
			return fmt.Errorf("pg: unexpected message %q during prepare", m.Type)
		}
	}
}

// ExecPrepared binds and executes a previously prepared statement
// (PG::Connection#exec_prepared).
func (c *Conn) ExecPrepared(name string, args ...any) (*Result, error) {
	params, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	msgs := [][]byte{
		EncodeBind("", name, params, nil),
		EncodeDescribePortal(""),
		EncodeExecute("", 0),
		EncodeSync(),
	}
	return c.runExtended(msgs)
}

// runExtended writes an extended-query message batch and reads its replies,
// tolerating ParseComplete / BindComplete / NoData / ParameterDescription
// preamble, assembling the Result, and consuming through ReadyForQuery.
func (c *Conn) runExtended(msgs [][]byte) (*Result, error) {
	if err := c.writeAll(msgs); err != nil {
		return nil, err
	}
	var desc *RowDescription
	var rows []*DataRow
	var result *Result
	var firstErr error
	for {
		m, err := c.nextSignificant()
		if err != nil {
			return nil, err
		}
		switch m.Type {
		case msgParseComplete:
			err = ParseParseComplete(m)
		case msgBindComplete:
			err = ParseBindComplete(m)
		case msgParamDescription:
			_, err = ParseParameterDescription(m)
		case msgNoData:
			err = ParseNoData(m)
		case msgRowDescription:
			desc, err = ParseRowDescription(m)
		case msgDataRow:
			var dr *DataRow
			dr, err = ParseDataRow(m)
			if err == nil {
				rows = append(rows, dr)
			}
		case msgCommandComplete:
			var tag string
			tag, err = ParseCommandComplete(m)
			if err == nil {
				result, err = NewResult(desc, rows, tag)
			}
		case msgEmptyQuery:
			err = ParseEmptyQueryResponse(m)
			if err == nil {
				result, err = NewResult(desc, rows, "")
			}
		case msgPortalSuspended:
			err = ParsePortalSuspended(m)
		case msgErrorResponse:
			var ef *ErrorFields
			ef, err = ParseErrorResponse(m)
			if err == nil {
				firstErr = ef.AsError()
			}
		case msgReadyForQuery:
			var st TransactionStatus
			st, err = ParseReadyForQuery(m)
			if err == nil {
				c.txStatus = st
			}
			if err != nil {
				return nil, err
			}
			if firstErr != nil {
				return nil, firstErr
			}
			if result == nil {
				return NewResult(desc, rows, "")
			}
			return result, nil
		default:
			return nil, fmt.Errorf("pg: unexpected message %q in extended query", m.Type)
		}
		if err != nil {
			return nil, err
		}
	}
}

// writeAll writes a batch of framed messages.
func (c *Conn) writeAll(msgs [][]byte) error {
	for _, m := range msgs {
		if err := c.write(m); err != nil {
			return err
		}
	}
	return nil
}

// encodeArgs turns Go arguments into text-format BindParams.
func encodeArgs(args []any) ([]BindParam, error) {
	params := make([]BindParam, len(args))
	for i, a := range args {
		v, err := EncodeParam(a)
		if err != nil {
			return nil, err
		}
		params[i] = BindParam{Value: v, Format: TextFormat}
	}
	return params, nil
}

// Terminate sends a Terminate message (PG::Connection#finish's protocol half).
func (c *Conn) Terminate() error { return c.write(EncodeTerminate()) }

// EscapeString is the connection method form of the package EscapeString.
func (c *Conn) EscapeString(s string) string { return EscapeString(s) }

// EscapeLiteral is the connection method form of the package EscapeLiteral.
func (c *Conn) EscapeLiteral(s string) string { return EscapeLiteral(s) }

// EscapeIdentifier is the connection method form of the package
// EscapeIdentifier.
func (c *Conn) EscapeIdentifier(s string) string { return EscapeIdentifier(s) }

// QuoteIdent is the connection method form of the package QuoteIdent.
func (c *Conn) QuoteIdent(s string) string { return QuoteIdent(s) }

// RoundTripper is the minimal seam for a caller that wants to intercept the raw
// frontend/backend byte exchange (for logging, a test double, or a non-socket
// transport). A Conn built over an io.ReadWriter satisfies the common case;
// RoundTrip lets a host substitute its own request/response transport.
type RoundTripper interface {
	// RoundTrip writes the frontend messages and returns the backend messages up
	// to the next synchronisation point.
	RoundTrip(frontend [][]byte) ([]Message, error)
}

// CancelRequest returns the bytes of a CancelRequest for this connection's
// backend key, to be sent on a *fresh* connection (never the query connection).
func (c *Conn) CancelRequest() ([]byte, error) {
	if c.key == nil {
		return nil, errors.New("pg: no BackendKeyData; cannot build CancelRequest")
	}
	return EncodeCancelRequest(c.key.ProcessID, c.key.SecretKey), nil
}

// Startup performs the post-StartupMessage handshake read loop up to
// ReadyForQuery, capturing ParameterStatus and BackendKeyData and driving any
// authentication via the supplied Authenticator. The StartupMessage itself must
// already have been written by the caller (it owns the parameter set).
func (c *Conn) Startup(auth Authenticator) error {
	for {
		m, err := c.nextSignificant()
		if err != nil {
			return err
		}
		switch m.Type {
		case msgAuthentication:
			a, err := ParseAuthentication(m)
			if err != nil {
				return err
			}
			if a.Kind == AuthOK {
				continue
			}
			if auth == nil {
				return fmt.Errorf("pg: authentication required (kind %d) but no Authenticator", a.Kind)
			}
			if err := auth.Handle(c, a); err != nil {
				return err
			}
		case msgBackendKeyData:
			k, err := ParseBackendKeyData(m)
			if err != nil {
				return err
			}
			c.key = k
		case msgReadyForQuery:
			st, err := ParseReadyForQuery(m)
			if err != nil {
				return err
			}
			c.txStatus = st
			return nil
		case msgErrorResponse:
			ef, err := ParseErrorResponse(m)
			if err != nil {
				return err
			}
			return ef.AsError()
		default:
			return fmt.Errorf("pg: unexpected message %q during startup", m.Type)
		}
	}
}
