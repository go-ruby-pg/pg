package pg

import (
	"strings"
	"testing"
)

func TestParseErrorResponse(t *testing.T) {
	body := []byte("SERROR\x00C23505\x00Mduplicate key\x00Ddetail\x00Hhint\x00\x00")
	ef, err := ParseErrorResponse(mustMsg('E', body))
	if err != nil {
		t.Fatal(err)
	}
	if ef.Severity() != "ERROR" || ef.SQLState() != "23505" || ef.Message() != "duplicate key" {
		t.Errorf("fields: %+v", ef.Fields)
	}
	if ef.Detail() != "detail" || ef.Hint() != "hint" {
		t.Errorf("detail/hint wrong")
	}
	if v, ok := ef.Get('S'); !ok || v != "ERROR" {
		t.Errorf("Get")
	}
	if _, ok := ef.Get('Z'); ok {
		t.Errorf("Get missing should be false")
	}
	// AsError formatting
	e := ef.AsError()
	if !strings.Contains(e.Error(), "ERROR:") || !strings.Contains(e.Error(), "23505") {
		t.Errorf("Error(): %q", e.Error())
	}
	// notice
	if _, err := ParseNoticeResponse(mustMsg('N', body)); err != nil {
		t.Errorf("notice: %v", err)
	}
	// wrong types
	if _, err := ParseErrorResponse(mustMsg('X', nil)); err != errBadType {
		t.Errorf("err bad type")
	}
	if _, err := ParseNoticeResponse(mustMsg('X', nil)); err != errBadType {
		t.Errorf("notice bad type")
	}
	// truncation: missing terminator
	if _, err := ParseErrorResponse(mustMsg('E', []byte("Sfoo"))); err == nil {
		t.Errorf("want value truncation")
	}
	// truncation: dangling code byte with no value
	if _, err := ParseErrorResponse(mustMsg('E', []byte("S"))); err == nil {
		t.Errorf("want code truncation")
	}
}

func TestErrorFormatNoSQLState(t *testing.T) {
	ef := &ErrorFields{Fields: map[byte]string{'M': "boom"}}
	e := ef.AsError()
	if e.Error() != "ERROR: boom" {
		t.Errorf("no-sqlstate default: %q", e.Error())
	}
	ef.Fields['S'] = "FATAL"
	if e.Error() != "FATAL: boom" {
		t.Errorf("severity used: %q", e.Error())
	}
}

// buildResult constructs a Result from field OIDs and text-format rows.
func buildResult(t *testing.T, names []string, oids []uint32, rows [][]string) *Result {
	t.Helper()
	fields := make([]FieldDescription, len(names))
	for i := range names {
		fields[i] = FieldDescription{Name: names[i], DataTypeOID: oids[i], Format: TextFormat, TypeModifier: -1}
	}
	desc := &RowDescription{Fields: fields}
	var drs []*DataRow
	for _, r := range rows {
		vals := make([][]byte, len(r))
		for i, cell := range r {
			if cell == "\x00NULL" {
				vals[i] = nil
			} else {
				vals[i] = []byte(cell)
			}
		}
		drs = append(drs, &DataRow{Values: vals})
	}
	res, err := NewResult(desc, drs, "SELECT "+itoa(len(rows)))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestResultAccessors(t *testing.T) {
	res := buildResult(t,
		[]string{"id", "name"},
		[]uint32{uint32(OIDInt4), uint32(OIDText)},
		[][]string{{"1", "alice"}, {"2", "\x00NULL"}})

	if res.Ntuples() != 2 || res.Nfields() != 2 {
		t.Errorf("counts")
	}
	if fs := res.Fields(); fs[0] != "id" || fs[1] != "name" {
		t.Errorf("fields")
	}
	if n, _ := res.Fname(0); n != "id" {
		t.Errorf("fname")
	}
	if _, err := res.Fname(9); err == nil {
		t.Errorf("fname oob")
	}
	if res.Fnumber("name") != 1 || res.Fnumber("nope") != -1 {
		t.Errorf("fnumber")
	}
	if ft, _ := res.Ftype(0); ft != OIDInt4 {
		t.Errorf("ftype")
	}
	if _, err := res.Ftype(9); err == nil {
		t.Errorf("ftype oob")
	}
	if fm, _ := res.Fmod(0); fm != -1 {
		t.Errorf("fmod")
	}
	if _, err := res.Fmod(9); err == nil {
		t.Errorf("fmod oob")
	}
	if v, _ := res.Getvalue(0, 0); v != int64(1) {
		t.Errorf("getvalue: %v", v)
	}
	if v, _ := res.Getvalue(0, 1); v != "alice" {
		t.Errorf("getvalue str")
	}
	if v, _ := res.Getvalue(1, 1); v != nil {
		t.Errorf("getvalue null")
	}
	if _, err := res.Getvalue(9, 0); err == nil {
		t.Errorf("getvalue row oob")
	}
	if _, err := res.Getvalue(0, 9); err == nil {
		t.Errorf("getvalue col oob")
	}
	if raw, _ := res.GetvalueRaw(0, 0); string(raw) != "1" {
		t.Errorf("getvalueraw")
	}
	if _, err := res.GetvalueRaw(9, 0); err == nil {
		t.Errorf("getvalueraw row oob")
	}
	if _, err := res.GetvalueRaw(0, 9); err == nil {
		t.Errorf("getvalueraw col oob")
	}
	if isnull, _ := res.Getisnull(1, 1); !isnull {
		t.Errorf("getisnull")
	}
	if isnull, _ := res.Getisnull(0, 0); isnull {
		t.Errorf("getisnull false")
	}
	if _, err := res.Getisnull(9, 0); err == nil {
		t.Errorf("getisnull row oob")
	}
	if _, err := res.Getisnull(0, 9); err == nil {
		t.Errorf("getisnull col oob")
	}
	if vals := res.Values(); len(vals) != 2 || vals[0][1] != "alice" {
		t.Errorf("values")
	}
	tup, _ := res.Tuple(0)
	if tup["id"] != int64(1) || tup["name"] != "alice" {
		t.Errorf("tuple: %v", tup)
	}
	if _, err := res.Tuple(9); err == nil {
		t.Errorf("tuple oob")
	}
	if res.CmdStatus() != "SELECT 2" {
		t.Errorf("cmdstatus: %q", res.CmdStatus())
	}
}

func TestResultEach(t *testing.T) {
	res := buildResult(t, []string{"id"}, []uint32{uint32(OIDInt4)}, [][]string{{"1"}, {"2"}})
	var ids []any
	if err := res.Each(func(m map[string]any) error { ids = append(ids, m["id"]); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Errorf("each count")
	}
	// error propagation
	sentinel := errBadType
	if err := res.Each(func(m map[string]any) error { return sentinel }); err != sentinel {
		t.Errorf("each error propagation")
	}
}

func TestCmdTuples(t *testing.T) {
	cases := map[string]int{
		"INSERT 0 5": 5,
		"UPDATE 3":   3,
		"DELETE 7":   7,
		"SELECT 42":  42,
		"BEGIN":      0,
		"":           0,
	}
	for tag, want := range cases {
		res, _ := NewResult(nil, nil, tag)
		if got := res.CmdTuples(); got != want {
			t.Errorf("cmd_tuples(%q)=%d want %d", tag, got, want)
		}
	}
}

func TestNewResultBinaryAndDecodeError(t *testing.T) {
	// binary format cell decoded via DecodeBinary
	desc := &RowDescription{Fields: []FieldDescription{{Name: "n", DataTypeOID: uint32(OIDInt4), Format: BinaryFormat}}}
	dr := &DataRow{Values: [][]byte{{0, 0, 0, 9}}}
	res, err := NewResult(desc, []*DataRow{dr}, "SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := res.Getvalue(0, 0); v != int64(9) {
		t.Errorf("binary cell: %v", v)
	}
	// decode error propagates (bad int4 binary length)
	badDR := &DataRow{Values: [][]byte{{0, 9}}}
	if _, err := NewResult(desc, []*DataRow{badDR}, "x"); err == nil {
		t.Errorf("want decode error")
	}
	// more cells than fields -> extra cells default to OIDText
	descNarrow := &RowDescription{Fields: []FieldDescription{{Name: "a", DataTypeOID: uint32(OIDText), Format: TextFormat}}}
	dr2 := &DataRow{Values: [][]byte{[]byte("x"), []byte("y")}}
	res2, err := NewResult(descNarrow, []*DataRow{dr2}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := res2.Getvalue(0, 1); v != "y" {
		t.Errorf("extra cell default text: %v", v)
	}
}
