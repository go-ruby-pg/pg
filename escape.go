package pg

import "strings"

// This file implements PG::Connection's escaping helpers as pure functions of
// their input, matching libpq's PQescapeStringConn / PQescapeLiteral /
// PQescapeIdentifier with standard_conforming_strings on (the modern default).

// EscapeString escapes a string for inclusion between existing single quotes,
// doubling embedded single quotes. With standard-conforming strings, backslashes
// are literal, so only the quote is doubled. This mirrors
// PG::Connection#escape_string / #escape.
func EscapeString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// EscapeLiteral wraps s in single quotes, doubling embedded quotes, mirroring
// PG::Connection#escape_literal. If s contains a backslash, an E'' escape-string
// prefix is emitted and backslashes are doubled, exactly as libpq does to remain
// correct regardless of the standard_conforming_strings setting.
func EscapeLiteral(s string) string {
	hasBackslash := strings.ContainsRune(s, '\\')
	var b strings.Builder
	if hasBackslash {
		b.WriteByte(' ')
		b.WriteByte('E')
	}
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			b.WriteString("''")
		case '\\':
			b.WriteString("\\\\")
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// EscapeIdentifier wraps s in double quotes, doubling embedded double quotes,
// mirroring PG::Connection#escape_identifier. QuoteIdent is an alias for the same
// operation (PG::Connection.quote_ident).
func EscapeIdentifier(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			b.WriteString(`""`)
		} else {
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// QuoteIdent quotes a possibly-qualified identifier. A dotted name like
// "schema.table" is quoted segment-by-segment ("schema"."table"), matching
// PG::Connection.quote_ident's handling of the array form only loosely; the
// scalar form here quotes the whole string as one identifier unless it contains
// a dot, in which case each dotted segment is quoted independently.
func QuoteIdent(s string) string {
	if !strings.Contains(s, ".") {
		return EscapeIdentifier(s)
	}
	parts := strings.Split(s, ".")
	for i, p := range parts {
		parts[i] = EscapeIdentifier(p)
	}
	return strings.Join(parts, ".")
}
