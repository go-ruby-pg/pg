package pg

// OID is a PostgreSQL type object identifier. The constants below are the
// stable, built-in OIDs (from pg_type.dat) the type decoders dispatch on.
type OID uint32

// Built-in scalar type OIDs.
const (
	OIDBool        OID = 16
	OIDBytea       OID = 17
	OIDChar        OID = 18
	OIDName        OID = 19
	OIDInt8        OID = 20
	OIDInt2        OID = 21
	OIDInt4        OID = 23
	OIDRegProc     OID = 24
	OIDText        OID = 25
	OIDOID         OID = 26
	OIDTID         OID = 27
	OIDXID         OID = 28
	OIDCID         OID = 29
	OIDJSON        OID = 114
	OIDXML         OID = 142
	OIDFloat4      OID = 700
	OIDFloat8      OID = 701
	OIDUnknown     OID = 705
	OIDMoney       OID = 790
	OIDMacaddr     OID = 829
	OIDInet        OID = 869
	OIDCIDR        OID = 650
	OIDBPChar      OID = 1042
	OIDVarchar     OID = 1043
	OIDDate        OID = 1082
	OIDTime        OID = 1083
	OIDTimestamp   OID = 1114
	OIDTimestamptz OID = 1184
	OIDInterval    OID = 1186
	OIDTimetz      OID = 1266
	OIDBit         OID = 1560
	OIDVarbit      OID = 1562
	OIDNumeric     OID = 1700
	OIDUUID        OID = 2950
	OIDJSONB       OID = 3802
)

// Built-in array type OIDs (the array-of-T alongside its element T).
const (
	OIDBoolArray        OID = 1000
	OIDByteaArray       OID = 1001
	OIDInt2Array        OID = 1005
	OIDInt4Array        OID = 1007
	OIDTextArray        OID = 1009
	OIDVarcharArray     OID = 1015
	OIDInt8Array        OID = 1016
	OIDFloat4Array      OID = 1021
	OIDFloat8Array      OID = 1022
	OIDOIDArray         OID = 1028
	OIDNumericArray     OID = 1231
	OIDTimestampArray   OID = 1115
	OIDDateArray        OID = 1182
	OIDTimestamptzArray OID = 1185
	OIDUUIDArray        OID = 2951
	OIDJSONArray        OID = 199
	OIDJSONBArray       OID = 3807
)

// arrayElem maps an array OID to its element OID, and reports whether oid is a
// known array type.
func arrayElem(oid OID) (OID, bool) {
	e, ok := arrayElemTable[oid]
	return e, ok
}

var arrayElemTable = map[OID]OID{
	OIDBoolArray:        OIDBool,
	OIDByteaArray:       OIDBytea,
	OIDInt2Array:        OIDInt2,
	OIDInt4Array:        OIDInt4,
	OIDInt8Array:        OIDInt8,
	OIDTextArray:        OIDText,
	OIDVarcharArray:     OIDVarchar,
	OIDFloat4Array:      OIDFloat4,
	OIDFloat8Array:      OIDFloat8,
	OIDOIDArray:         OIDOID,
	OIDNumericArray:     OIDNumeric,
	OIDTimestampArray:   OIDTimestamp,
	OIDTimestamptzArray: OIDTimestamptz,
	OIDDateArray:        OIDDate,
	OIDUUIDArray:        OIDUUID,
	OIDJSONArray:        OIDJSON,
	OIDJSONBArray:       OIDJSONB,
}
