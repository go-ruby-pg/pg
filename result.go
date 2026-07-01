package pg

import "fmt"

// Result is the pure value view of a query outcome, mirroring PG::Result. It
// bundles the RowDescription (column metadata), the decoded rows, and the command
// tag, and offers the ntuples / nfields / fields / getvalue / values / [] surface
// PG::Result exposes. Values are decoded per column format/OID via DecodeText /
// DecodeBinary; a NULL cell is nil.
type Result struct {
	fields  []FieldDescription
	rows    [][]any // decoded values; nil element == NULL
	rawRows [][][]byte
	tag     string
}

// NewResult assembles a Result from a RowDescription and the raw DataRows,
// decoding every cell using its column's OID and format. A nil desc (a
// command with no row description, e.g. INSERT) yields a zero-column Result.
func NewResult(desc *RowDescription, rows []*DataRow, tag string) (*Result, error) {
	r := &Result{tag: tag}
	if desc != nil {
		r.fields = desc.Fields
	}
	for _, dr := range rows {
		decoded := make([]any, len(dr.Values))
		raw := make([][]byte, len(dr.Values))
		for i, cell := range dr.Values {
			raw[i] = cell
			if cell == nil {
				decoded[i] = nil
				continue
			}
			oid := OIDText
			format := TextFormat
			if i < len(r.fields) {
				oid = OID(r.fields[i].DataTypeOID)
				format = r.fields[i].Format
			}
			v, err := decodeCell(oid, format, cell)
			if err != nil {
				return nil, err
			}
			decoded[i] = v
		}
		r.rows = append(r.rows, decoded)
		r.rawRows = append(r.rawRows, raw)
	}
	return r, nil
}

func decodeCell(oid OID, format Format, cell []byte) (any, error) {
	if format == BinaryFormat {
		return DecodeBinary(oid, cell)
	}
	return DecodeText(oid, cell)
}

// Ntuples returns the number of rows (PG::Result#ntuples / #num_tuples).
func (r *Result) Ntuples() int { return len(r.rows) }

// Nfields returns the number of columns (PG::Result#nfields / #num_fields).
func (r *Result) Nfields() int { return len(r.fields) }

// Fields returns the column names (PG::Result#fields).
func (r *Result) Fields() []string {
	names := make([]string, len(r.fields))
	for i, f := range r.fields {
		names[i] = f.Name
	}
	return names
}

// Fname returns the name of column i (PG::Result#fname).
func (r *Result) Fname(i int) (string, error) {
	if i < 0 || i >= len(r.fields) {
		return "", fmt.Errorf("pg: field index %d out of range", i)
	}
	return r.fields[i].Name, nil
}

// Fnumber returns the index of the named column, or -1 if absent
// (PG::Result#fnumber returns nil; -1 is the Go-idiomatic not-found).
func (r *Result) Fnumber(name string) int {
	for i, f := range r.fields {
		if f.Name == name {
			return i
		}
	}
	return -1
}

// Ftype returns the type OID of column i (PG::Result#ftype).
func (r *Result) Ftype(i int) (OID, error) {
	if i < 0 || i >= len(r.fields) {
		return 0, fmt.Errorf("pg: field index %d out of range", i)
	}
	return OID(r.fields[i].DataTypeOID), nil
}

// Fmod returns the type modifier of column i (PG::Result#fmod).
func (r *Result) Fmod(i int) (int32, error) {
	if i < 0 || i >= len(r.fields) {
		return 0, fmt.Errorf("pg: field index %d out of range", i)
	}
	return r.fields[i].TypeModifier, nil
}

// Getvalue returns the decoded value at (row, col) (PG::Result#getvalue). A NULL
// is nil.
func (r *Result) Getvalue(row, col int) (any, error) {
	if row < 0 || row >= len(r.rows) {
		return nil, fmt.Errorf("pg: row index %d out of range", row)
	}
	if col < 0 || col >= len(r.rows[row]) {
		return nil, fmt.Errorf("pg: column index %d out of range", col)
	}
	return r.rows[row][col], nil
}

// GetvalueRaw returns the raw wire bytes at (row, col), or nil for NULL.
func (r *Result) GetvalueRaw(row, col int) ([]byte, error) {
	if row < 0 || row >= len(r.rawRows) {
		return nil, fmt.Errorf("pg: row index %d out of range", row)
	}
	if col < 0 || col >= len(r.rawRows[row]) {
		return nil, fmt.Errorf("pg: column index %d out of range", col)
	}
	return r.rawRows[row][col], nil
}

// Getisnull reports whether the cell at (row, col) is SQL NULL
// (PG::Result#getisnull).
func (r *Result) Getisnull(row, col int) (bool, error) {
	if row < 0 || row >= len(r.rawRows) {
		return false, fmt.Errorf("pg: row index %d out of range", row)
	}
	if col < 0 || col >= len(r.rawRows[row]) {
		return false, fmt.Errorf("pg: column index %d out of range", col)
	}
	return r.rawRows[row][col] == nil, nil
}

// Values returns every row as a slice of decoded value slices
// (PG::Result#values).
func (r *Result) Values() [][]any {
	out := make([][]any, len(r.rows))
	for i, row := range r.rows {
		out[i] = append([]any(nil), row...)
	}
	return out
}

// Tuple returns row i as a name→value map (PG::Result#[] / #tuple). Duplicate
// column names collapse to the last occurrence, matching Ruby's Hash.
func (r *Result) Tuple(i int) (map[string]any, error) {
	if i < 0 || i >= len(r.rows) {
		return nil, fmt.Errorf("pg: row index %d out of range", i)
	}
	m := make(map[string]any, len(r.fields))
	for c, f := range r.fields {
		m[f.Name] = r.rows[i][c]
	}
	return m, nil
}

// Each applies fn to every row as a name→value map (PG::Result#each).
func (r *Result) Each(fn func(map[string]any) error) error {
	for i := range r.rows {
		t, err := r.Tuple(i)
		if err != nil {
			return err
		}
		if err := fn(t); err != nil {
			return err
		}
	}
	return nil
}

// CmdTuples parses the affected-row count from the command tag
// (PG::Result#cmd_tuples): the last integer of "INSERT 0 N" / "UPDATE N" /
// "DELETE N" / "SELECT N". A tag without a count returns 0.
func (r *Result) CmdTuples() int {
	n := 0
	seen := false
	for i := 0; i < len(r.tag); i++ {
		c := r.tag[i]
		if c == ' ' {
			n = 0
			seen = false
			continue
		}
		if c < '0' || c > '9' {
			n = 0
			seen = false
			continue
		}
		n = n*10 + int(c-'0')
		seen = true
	}
	if !seen {
		return 0
	}
	return n
}

// CmdStatus returns the raw command tag (PG::Result#cmd_status).
func (r *Result) CmdStatus() string { return r.tag }
