package pg

// This file encodes the frontend messages a client sends to the server. Each
// function returns the exact bytes PostgreSQL expects on the wire, so a host can
// write them to its socket verbatim. The framing (type byte + Int32 length) is
// handled by writeBuf.frame.

// StartupParams are the key/value pairs of a StartupMessage. "user" is
// mandatory; "database", "application_name", "client_encoding", etc. are
// optional. PostgreSQL terminates the list with an empty key.
type StartupParams map[string]string

// EncodeStartup builds an untyped StartupMessage: the protocol version followed
// by NUL-terminated key/value C strings, then a final NUL. "user" is always
// emitted first (PostgreSQL requires it and libpq places it first); the
// remaining keys follow in sorted order for a deterministic byte stream.
func EncodeStartup(params StartupParams) []byte {
	var w writeBuf
	w.int32(protocolVersion)
	if u, ok := params["user"]; ok {
		w.string("user")
		w.string(u)
	}
	for _, k := range sortedKeysExcept(params, "user") {
		w.string(k)
		w.string(params[k])
	}
	w.byte(0)
	return w.frame(0)
}

// EncodeSSLRequest builds the untyped SSLRequest (magic 80877103). The server
// answers with a single byte 'S' (proceed with TLS) or 'N' (plaintext).
func EncodeSSLRequest() []byte {
	var w writeBuf
	w.int32(80877103)
	return w.frame(0)
}

// EncodeCancelRequest builds the untyped CancelRequest (magic 80877102) carrying
// the process ID and secret key from a prior BackendKeyData.
func EncodeCancelRequest(processID, secretKey int32) []byte {
	var w writeBuf
	w.int32(80877102)
	w.int32(processID)
	w.int32(secretKey)
	return w.frame(0)
}

// EncodePassword builds a PasswordMessage carrying a (possibly MD5- or
// cleartext-) password string. It is also the envelope PostgreSQL reuses for
// SASL; see EncodeSASLInitialResponse / EncodeSASLResponse for those.
func EncodePassword(password string) []byte {
	var w writeBuf
	w.string(password)
	return w.frame(msgPassword)
}

// EncodeSASLInitialResponse builds the first SASL message: the selected
// mechanism name, then an Int32 length-prefixed client-first message (or -1 when
// absent).
func EncodeSASLInitialResponse(mechanism string, initial []byte) []byte {
	var w writeBuf
	w.string(mechanism)
	if initial == nil {
		w.int32(-1)
	} else {
		w.int32(int32(len(initial)))
		w.bytes(initial)
	}
	return w.frame(msgPassword)
}

// EncodeSASLResponse builds a subsequent SASL message (the client-final message
// body, with no length prefix — the frame length delimits it).
func EncodeSASLResponse(data []byte) []byte {
	var w writeBuf
	w.bytes(data)
	return w.frame(msgPassword)
}

// EncodeQuery builds a simple-query message.
func EncodeQuery(sql string) []byte {
	var w writeBuf
	w.string(sql)
	return w.frame(msgQuery)
}

// EncodeParse builds a Parse message: the destination prepared-statement name
// (empty for the unnamed statement), the query text, and the OIDs of any
// parameter types the client wishes to pin (an OID of 0 lets the server infer).
func EncodeParse(name, sql string, paramOIDs []uint32) []byte {
	var w writeBuf
	w.string(name)
	w.string(sql)
	w.int16(int16(len(paramOIDs)))
	for _, oid := range paramOIDs {
		w.int32(int32(oid))
	}
	return w.frame(msgParse)
}

// BindParam is a single Bind parameter: a value and its wire format. A nil Value
// encodes as SQL NULL.
type BindParam struct {
	Value  []byte
	Format Format
}

// EncodeBind builds a Bind message binding a prepared statement to a portal. The
// parameter formats are emitted per-parameter; the result-column formats request
// text or binary for each returned column (an empty slice means "all text", a
// single element means "apply to all").
func EncodeBind(portal, stmt string, params []BindParam, resultFormats []Format) []byte {
	var w writeBuf
	w.string(portal)
	w.string(stmt)
	w.int16(int16(len(params)))
	for _, p := range params {
		w.int16(int16(p.Format))
	}
	w.int16(int16(len(params)))
	for _, p := range params {
		if p.Value == nil {
			w.int32(-1)
		} else {
			w.int32(int32(len(p.Value)))
			w.bytes(p.Value)
		}
	}
	w.int16(int16(len(resultFormats)))
	for _, f := range resultFormats {
		w.int16(int16(f))
	}
	return w.frame(msgBind)
}

// describeKind selects whether a Describe/Close targets a portal or statement.
const (
	describePortal    = 'P'
	describeStatement = 'S'
)

// EncodeDescribeStatement builds a Describe for a prepared statement, eliciting a
// ParameterDescription and a RowDescription (or NoData).
func EncodeDescribeStatement(name string) []byte {
	return encodeDescribeClose(msgDescribe, describeStatement, name)
}

// EncodeDescribePortal builds a Describe for a portal, eliciting a RowDescription
// (or NoData).
func EncodeDescribePortal(name string) []byte {
	return encodeDescribeClose(msgDescribe, describePortal, name)
}

// EncodeCloseStatement builds a Close for a prepared statement.
func EncodeCloseStatement(name string) []byte {
	return encodeDescribeClose(msgClose, describeStatement, name)
}

// EncodeClosePortal builds a Close for a portal.
func EncodeClosePortal(name string) []byte {
	return encodeDescribeClose(msgClose, describePortal, name)
}

func encodeDescribeClose(msgType, kind byte, name string) []byte {
	var w writeBuf
	w.byte(kind)
	w.string(name)
	return w.frame(msgType)
}

// EncodeExecute builds an Execute for a portal. maxRows == 0 means "fetch all";
// a positive limit makes the server reply with PortalSuspended once reached.
func EncodeExecute(portal string, maxRows int32) []byte {
	var w writeBuf
	w.string(portal)
	w.int32(maxRows)
	return w.frame(msgExecute)
}

// EncodeSync builds a Sync message, closing an extended-query cycle so the server
// emits ReadyForQuery.
func EncodeSync() []byte {
	var w writeBuf
	return w.frame(msgSync)
}

// EncodeFlush builds a Flush message, forcing the server to send any buffered
// output without ending the transaction cycle.
func EncodeFlush() []byte {
	var w writeBuf
	return w.frame(msgFlush)
}

// EncodeTerminate builds a Terminate message, a graceful connection shutdown.
func EncodeTerminate() []byte {
	var w writeBuf
	return w.frame(msgTerminate)
}

// EncodeCopyData wraps a chunk of COPY payload.
func EncodeCopyData(data []byte) []byte {
	var w writeBuf
	w.bytes(data)
	return w.frame(msgCopyData)
}

// EncodeCopyDone signals the end of COPY-in data.
func EncodeCopyDone() []byte {
	var w writeBuf
	return w.frame(msgCopyDone)
}

// EncodeCopyFail aborts a COPY-in with a diagnostic message.
func EncodeCopyFail(reason string) []byte {
	var w writeBuf
	w.string(reason)
	return w.frame(msgCopyFail)
}
