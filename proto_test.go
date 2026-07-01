package pg

import (
	"bytes"
	"testing"
)

func TestEncodeStartupBytes(t *testing.T) {
	got := EncodeStartup(StartupParams{"user": "alice", "database": "shop"})
	// Untyped: Int32 len, Int32 version, "user\0alice\0database\0shop\0\0".
	want := []byte{
		0, 0, 0, 0, // len placeholder, fixed below
		0, 3, 0, 0, // protocol 196608
	}
	body := []byte("user\x00alice\x00database\x00shop\x00\x00")
	want = append(want[:4], append([]byte{0, 3, 0, 0}, body...)...)
	// patch the length prefix
	total := len(want)
	want[0] = byte(total >> 24)
	want[1] = byte(total >> 16)
	want[2] = byte(total >> 8)
	want[3] = byte(total)
	if !bytes.Equal(got, want) {
		t.Fatalf("startup mismatch:\n got %v\nwant %v", got, want)
	}
}

func TestTransactionStatusString(t *testing.T) {
	cases := map[TransactionStatus]string{
		TxnIdle:   "idle",
		TxnActive: "active",
		TxnError:  "error",
		'X':       "unknown('X')",
	}
	for st, want := range cases {
		if got := st.String(); got != want {
			t.Errorf("%q: got %q want %q", byte(st), got, want)
		}
	}
}
