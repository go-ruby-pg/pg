package pg

import "fmt"

// ErrorFields holds every field of an ErrorResponse / NoticeResponse, keyed by
// the single-byte field identifier PostgreSQL uses on the wire. The named
// accessors below expose the common ones; PG::Result#error_field(fieldcode) and
// PG::Error map onto exactly this set.
type ErrorFields struct {
	// Fields maps a field-type byte to its value, preserving every field the
	// server sent (including ones without a named accessor).
	Fields map[byte]string
}

// Field-type bytes (see the PostgreSQL protocol's Error and Notice Message
// Fields). These mirror PG::Result's PG_DIAG_* constants.
const (
	FieldSeverity         = 'S'
	FieldSeverityNonLocal = 'V' // non-localized severity (PG 9.6+)
	FieldSQLState         = 'C'
	FieldMessage          = 'M'
	FieldDetail           = 'D'
	FieldHint             = 'H'
	FieldPosition         = 'P'
	FieldInternalPosition = 'p'
	FieldInternalQuery    = 'q'
	FieldWhere            = 'W'
	FieldSchemaName       = 's'
	FieldTableName        = 't'
	FieldColumnName       = 'c'
	FieldDataTypeName     = 'd'
	FieldConstraintName   = 'n'
	FieldFile             = 'F'
	FieldLine             = 'L'
	FieldRoutine          = 'R'
)

// ParseErrorResponse decodes an 'E' message body into its fields.
func ParseErrorResponse(m Message) (*ErrorFields, error) {
	if m.Type != msgErrorResponse {
		return nil, errBadType
	}
	return parseFields(m.Body)
}

// ParseNoticeResponse decodes an 'N' message body into its fields.
func ParseNoticeResponse(m Message) (*ErrorFields, error) {
	if m.Type != msgNoticeResponse {
		return nil, errBadType
	}
	return parseFields(m.Body)
}

func parseFields(body []byte) (*ErrorFields, error) {
	r := &readBuf{b: body}
	ef := &ErrorFields{Fields: map[byte]string{}}
	for {
		code := r.byte()
		if r.fail() {
			return nil, r.err
		}
		if code == 0 {
			break
		}
		val := r.string()
		if r.fail() {
			return nil, r.err
		}
		ef.Fields[code] = val
	}
	return ef, nil
}

// Get returns the value of a field and whether it was present.
func (e *ErrorFields) Get(code byte) (string, bool) {
	v, ok := e.Fields[code]
	return v, ok
}

// Severity returns the localized severity (ERROR, FATAL, WARNING, NOTICE, ...).
func (e *ErrorFields) Severity() string { return e.Fields[FieldSeverity] }

// SQLState returns the five-character SQLSTATE code.
func (e *ErrorFields) SQLState() string { return e.Fields[FieldSQLState] }

// Message returns the primary human-readable error message.
func (e *ErrorFields) Message() string { return e.Fields[FieldMessage] }

// Detail returns the optional secondary detail message.
func (e *ErrorFields) Detail() string { return e.Fields[FieldDetail] }

// Hint returns the optional hint.
func (e *ErrorFields) Hint() string { return e.Fields[FieldHint] }

// Error is a PG::Error-like view of an ErrorResponse; it satisfies the Go error
// interface, formatting as "SEVERITY: message (SQLSTATE)".
type Error struct {
	*ErrorFields
}

// AsError wraps the fields as a Go error.
func (e *ErrorFields) AsError() *Error { return &Error{ErrorFields: e} }

func (e *Error) Error() string {
	sev := e.Severity()
	if sev == "" {
		sev = "ERROR"
	}
	if code := e.SQLState(); code != "" {
		return fmt.Sprintf("%s: %s (%s)", sev, e.Message(), code)
	}
	return fmt.Sprintf("%s: %s", sev, e.Message())
}
