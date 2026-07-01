package pg

import (
	"fmt"
	"io"
)

// This file decodes the backend messages a server sends. A raw message is a type
// byte, an Int32 length, and a body; ReadMessage frames one off an io.Reader and
// Parse* turn a body into a typed struct.

// Message is a framed, undecoded backend message: its type byte and body (the
// bytes after the length prefix). The length prefix itself is not retained.
type Message struct {
	Type byte
	Body []byte
}

// ReadMessage reads one framed backend message from r. It returns io.EOF only
// when r is at a clean message boundary; a truncated header or body yields
// io.ErrUnexpectedEOF.
func ReadMessage(r io.Reader) (Message, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return Message{}, io.ErrUnexpectedEOF
		}
		return Message{}, err
	}
	length := int(uint32(hdr[1])<<24 | uint32(hdr[2])<<16 | uint32(hdr[3])<<8 | uint32(hdr[4]))
	if length < 4 {
		return Message{}, fmt.Errorf("pg: invalid message length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return Message{}, io.ErrUnexpectedEOF
	}
	return Message{Type: hdr[0], Body: body}, nil
}

// --- Authentication ---------------------------------------------------------

// AuthType classifies an Authentication message.
type AuthType int32

// Authentication is a decoded 'R' message. Kind selects the variant; the
// remaining fields are populated as relevant.
type Authentication struct {
	Kind AuthType
	// Salt holds the 4-byte MD5 salt when Kind == AuthMD5Password.
	Salt []byte
	// Mechanisms lists the offered SASL mechanisms when Kind == AuthSASL.
	Mechanisms []string
	// Data holds the SASL server payload for AuthSASLContinue / AuthSASLFinal.
	Data []byte
}

// Exported AuthType values mirror the protocol sub-codes.
const (
	AuthOK                = AuthType(authOK)
	AuthKerberosV5        = AuthType(authKerberosV5)
	AuthCleartextPassword = AuthType(authCleartextPassword)
	AuthMD5Password       = AuthType(authMD5Password)
	AuthSCMCredential     = AuthType(authSCMCredential)
	AuthGSS               = AuthType(authGSS)
	AuthGSSContinue       = AuthType(authGSSContinue)
	AuthSSPI              = AuthType(authSSPI)
	AuthSASL              = AuthType(authSASL)
	AuthSASLContinue      = AuthType(authSASLContinue)
	AuthSASLFinal         = AuthType(authSASLFinal)
)

// ParseAuthentication decodes an 'R' message body.
func ParseAuthentication(m Message) (*Authentication, error) {
	if m.Type != msgAuthentication {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	a := &Authentication{Kind: AuthType(r.int32())}
	switch a.Kind {
	case AuthMD5Password:
		a.Salt = append([]byte(nil), r.next(4)...)
	case AuthSASL:
		for {
			name := r.string()
			if r.fail() || name == "" {
				break
			}
			a.Mechanisms = append(a.Mechanisms, name)
		}
	case AuthSASLContinue, AuthSASLFinal:
		a.Data = append([]byte(nil), r.b...)
		r.b = nil
	}
	if r.fail() {
		return nil, r.err
	}
	return a, nil
}

// --- ParameterStatus / BackendKeyData / ReadyForQuery -----------------------

// ParameterStatus is a decoded 'S' message: a runtime parameter and its value.
type ParameterStatus struct {
	Name, Value string
}

// ParseParameterStatus decodes an 'S' message body.
func ParseParameterStatus(m Message) (*ParameterStatus, error) {
	if m.Type != msgParameterStatus {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	p := &ParameterStatus{Name: r.string(), Value: r.string()}
	if r.fail() {
		return nil, r.err
	}
	return p, nil
}

// BackendKeyData is a decoded 'K' message: the cancellation key for this
// connection.
type BackendKeyData struct {
	ProcessID int32
	SecretKey int32
}

// ParseBackendKeyData decodes a 'K' message body.
func ParseBackendKeyData(m Message) (*BackendKeyData, error) {
	if m.Type != msgBackendKeyData {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	k := &BackendKeyData{ProcessID: r.int32(), SecretKey: r.int32()}
	if r.fail() {
		return nil, r.err
	}
	return k, nil
}

// ParseReadyForQuery decodes a 'Z' message body into its transaction status.
func ParseReadyForQuery(m Message) (TransactionStatus, error) {
	if m.Type != msgReadyForQuery {
		return 0, errBadType
	}
	r := &readBuf{b: m.Body}
	s := TransactionStatus(r.byte())
	if r.fail() {
		return 0, r.err
	}
	return s, nil
}

// --- RowDescription / DataRow -----------------------------------------------

// FieldDescription describes one column of a RowDescription.
type FieldDescription struct {
	Name         string
	TableOID     uint32
	AttrNumber   int16
	DataTypeOID  uint32
	DataTypeSize int16
	TypeModifier int32
	Format       Format
}

// RowDescription is a decoded 'T' message.
type RowDescription struct {
	Fields []FieldDescription
}

// ParseRowDescription decodes a 'T' message body.
func ParseRowDescription(m Message) (*RowDescription, error) {
	if m.Type != msgRowDescription {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	n := int(r.int16())
	rd := &RowDescription{}
	if n > 0 {
		rd.Fields = make([]FieldDescription, 0, n)
	}
	for i := 0; i < n; i++ {
		f := FieldDescription{
			Name:         r.string(),
			TableOID:     uint32(r.int32()),
			AttrNumber:   r.int16(),
			DataTypeOID:  uint32(r.int32()),
			DataTypeSize: r.int16(),
			TypeModifier: r.int32(),
			Format:       Format(r.int16()),
		}
		rd.Fields = append(rd.Fields, f)
	}
	if r.fail() {
		return nil, r.err
	}
	return rd, nil
}

// DataRow is a decoded 'D' message: the raw column values of one row. A nil
// element is SQL NULL.
type DataRow struct {
	Values [][]byte
}

// ParseDataRow decodes a 'D' message body.
func ParseDataRow(m Message) (*DataRow, error) {
	if m.Type != msgDataRow {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	n := int(r.int16())
	dr := &DataRow{}
	if n > 0 {
		dr.Values = make([][]byte, 0, n)
	}
	for i := 0; i < n; i++ {
		length := int(r.int32())
		if length < 0 {
			dr.Values = append(dr.Values, nil)
			continue
		}
		dr.Values = append(dr.Values, append([]byte(nil), r.next(length)...))
	}
	if r.fail() {
		return nil, r.err
	}
	return dr, nil
}

// --- CommandComplete / NotificationResponse ---------------------------------

// ParseCommandComplete decodes a 'C' message body into its command tag (for
// example "INSERT 0 1" or "SELECT 3").
func ParseCommandComplete(m Message) (string, error) {
	if m.Type != msgCommandComplete {
		return "", errBadType
	}
	r := &readBuf{b: m.Body}
	tag := r.string()
	if r.fail() {
		return "", r.err
	}
	return tag, nil
}

// NotificationResponse is a decoded 'A' message from LISTEN/NOTIFY.
type NotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

// ParseNotificationResponse decodes an 'A' message body.
func ParseNotificationResponse(m Message) (*NotificationResponse, error) {
	if m.Type != msgNotification {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	n := &NotificationResponse{ProcessID: r.int32(), Channel: r.string(), Payload: r.string()}
	if r.fail() {
		return nil, r.err
	}
	return n, nil
}

// --- ParameterDescription ---------------------------------------------------

// ParameterDescription is a decoded 't' message: the OIDs a prepared statement's
// parameters were inferred (or pinned) to.
type ParameterDescription struct {
	ParamOIDs []uint32
}

// ParseParameterDescription decodes a 't' message body.
func ParseParameterDescription(m Message) (*ParameterDescription, error) {
	if m.Type != msgParamDescription {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	n := int(r.int16())
	pd := &ParameterDescription{}
	if n > 0 {
		pd.ParamOIDs = make([]uint32, 0, n)
	}
	for i := 0; i < n; i++ {
		pd.ParamOIDs = append(pd.ParamOIDs, uint32(r.int32()))
	}
	if r.fail() {
		return nil, r.err
	}
	return pd, nil
}

// --- Copy responses ---------------------------------------------------------

// CopyResponse is a decoded CopyInResponse ('G') / CopyOutResponse ('H') /
// CopyBothResponse ('W'). OverallFormat is 0 for text COPY, 1 for binary;
// ColumnFormats gives the per-column format codes.
type CopyResponse struct {
	Type          byte
	OverallFormat int8
	ColumnFormats []Format
}

// ParseCopyResponse decodes a CopyInResponse / CopyOutResponse / CopyBothResponse
// body.
func ParseCopyResponse(m Message) (*CopyResponse, error) {
	if m.Type != msgCopyInResp && m.Type != msgCopyOutResp && m.Type != msgCopyBothResp {
		return nil, errBadType
	}
	r := &readBuf{b: m.Body}
	c := &CopyResponse{Type: m.Type, OverallFormat: int8(r.byte())}
	n := int(r.int16())
	if n > 0 {
		c.ColumnFormats = make([]Format, 0, n)
	}
	for i := 0; i < n; i++ {
		c.ColumnFormats = append(c.ColumnFormats, Format(r.int16()))
	}
	if r.fail() {
		return nil, r.err
	}
	return c, nil
}

// ParseCopyData decodes a 'd' message body, returning its raw payload.
func ParseCopyData(m Message) ([]byte, error) {
	if m.Type != msgCopyData {
		return nil, errBadType
	}
	return append([]byte(nil), m.Body...), nil
}

// --- Trivial (bodyless) messages --------------------------------------------

// verifyEmpty confirms m is of the wanted type; its body is ignored (these
// messages carry none).
func verifyEmpty(m Message, want byte) error {
	if m.Type != want {
		return errBadType
	}
	return nil
}

// ParseBindComplete verifies a '2' message.
func ParseBindComplete(m Message) error { return verifyEmpty(m, msgBindComplete) }

// ParseParseComplete verifies a '1' message.
func ParseParseComplete(m Message) error { return verifyEmpty(m, msgParseComplete) }

// ParseCloseComplete verifies a '3' message.
func ParseCloseComplete(m Message) error { return verifyEmpty(m, msgCloseComplete) }

// ParseNoData verifies an 'n' message.
func ParseNoData(m Message) error { return verifyEmpty(m, msgNoData) }

// ParseEmptyQueryResponse verifies an 'I' message.
func ParseEmptyQueryResponse(m Message) error { return verifyEmpty(m, msgEmptyQuery) }

// ParsePortalSuspended verifies an 's' message.
func ParsePortalSuspended(m Message) error { return verifyEmpty(m, msgPortalSuspended) }

// ParseCopyDone verifies a 'c' message.
func ParseCopyDone(m Message) error { return verifyEmpty(m, msgCopyDone) }
