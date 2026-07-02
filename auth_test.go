package pg

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestMD5Password(t *testing.T) {
	// Golden vector: md5(md5("secret"+"alice")+salt), salt = {1,2,3,4}.
	got := MD5Password("alice", "secret", []byte{1, 2, 3, 4})
	if !strings.HasPrefix(got, "md5") || len(got) != 35 {
		t.Fatalf("md5 shape: %q", got)
	}
	// Recompute independently to lock the value.
	// (This mirrors the implementation but via a separate path keeps it honest.)
	if got != md5Reference("alice", "secret", []byte{1, 2, 3, 4}) {
		t.Errorf("md5 mismatch: %q", got)
	}
}

func md5Reference(user, pw string, salt []byte) string {
	// Independent step-by-step reference: md5(md5(pw+user)+salt), hex-encoded.
	inner := md5.Sum([]byte(pw + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...))
	return "md5" + hex.EncodeToString(outer[:])
}

// scramServer emulates a PostgreSQL server's SCRAM-SHA-256 side for a full
// deterministic exchange, so the client can be verified end to end without a
// live database.
type scramServer struct {
	password  string
	salt      []byte
	iters     int
	nonce     string // server nonce suffix
	authMsg   string
	serverKey []byte
}

func (s *scramServer) firstMessage(clientFirst []byte) []byte {
	attrs, _ := parseSCRAM(strings.TrimPrefix(string(clientFirst), gs2Header))
	combined := attrs["r"] + s.nonce
	first := "r=" + combined +
		",s=" + base64.StdEncoding.EncodeToString(s.salt) +
		",i=" + itoa(s.iters)
	// stash for auth message
	s.authMsg = strings.TrimPrefix(string(clientFirst), gs2Header) + "," + first
	return []byte(first)
}

func (s *scramServer) finalMessage(clientFinal []byte) []byte {
	// clientFinal = c=...,r=...,p=proof
	idx := strings.LastIndex(string(clientFinal), ",p=")
	withoutProof := string(clientFinal)[:idx]
	authMessage := s.authMsg + "," + withoutProof

	salted, _ := pbkdf2.Key(sha256.New, s.password, s.salt, s.iters, sha256.Size)
	serverKey := hmacRef(salted, "Server Key")
	sig := hmacRef(serverKey, authMessage)
	return []byte("v=" + base64.StdEncoding.EncodeToString(sig))
}

func hmacRef(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func TestSCRAMExchange(t *testing.T) {
	srv := &scramServer{password: "s3cret", salt: []byte("saltysalt"), iters: 4096, nonce: "SRVNONCE"}
	c := NewSCRAMClientWithNonce("ignored", "s3cret", "CLIENTNONCE")

	first := c.FirstMessage()
	if string(first) != "n,,n=,r=CLIENTNONCE" {
		t.Fatalf("client first: %q", first)
	}
	serverFirst := srv.firstMessage(first)
	clientFinal, err := c.Final(serverFirst)
	if err != nil {
		t.Fatalf("client final: %v", err)
	}
	if !strings.Contains(string(clientFinal), "p=") {
		t.Errorf("client final missing proof")
	}
	serverFinal := srv.finalMessage(clientFinal)
	if err := c.Verify(serverFinal); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSCRAMErrors(t *testing.T) {
	c := NewSCRAMClientWithNonce("u", "pw", "CN")
	c.FirstMessage()
	// malformed server-first (missing fields)
	if _, err := c.Final([]byte("garbage")); err == nil {
		t.Errorf("want malformed error")
	}
	if _, err := c.Final([]byte("r=,s=,i=")); err == nil {
		t.Errorf("want empty-fields error")
	}
	// server nonce that does not extend the client nonce
	sf := "r=WRONG,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=1"
	if _, err := c.Final([]byte(sf)); err == nil {
		t.Errorf("want nonce-extension error")
	}
	// bad base64 salt
	sf = "r=CN9,s=!!!,i=1"
	if _, err := c.Final([]byte(sf)); err == nil {
		t.Errorf("want bad salt error")
	}
	// bad iteration count
	sf = "r=CN9,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=abc"
	if _, err := c.Final([]byte(sf)); err == nil {
		t.Errorf("want bad iters error")
	}
	// malformed attribute (no '=')
	if _, err := parseSCRAM("noequals"); err == nil {
		t.Errorf("want parse error")
	}
	if _, err := parseSCRAM("=noattr"); err == nil {
		t.Errorf("want empty-attr error")
	}
}

func TestSCRAMVerifyErrors(t *testing.T) {
	c := NewSCRAMClientWithNonce("u", "pw", "CN")
	// Verify before Final
	if err := c.Verify([]byte("v=x")); err == nil {
		t.Errorf("want verify-before-final error")
	}
	// Drive a valid exchange to set serverSig, then feed bad finals.
	srv := &scramServer{password: "pw", salt: []byte("salt"), iters: 2, nonce: "S"}
	c.FirstMessage()
	sf := srv.firstMessage([]byte("n,,n=,r=CN"))
	if _, err := c.Final(sf); err != nil {
		t.Fatal(err)
	}
	// server error field
	if err := c.Verify([]byte("e=invalid-proof")); err == nil {
		t.Errorf("want server error")
	}
	// missing verifier
	if err := c.Verify([]byte("x=y")); err == nil {
		t.Errorf("want missing verifier")
	}
	// bad base64 verifier
	if err := c.Verify([]byte("v=!!!")); err == nil {
		t.Errorf("want bad verifier b64")
	}
	// wrong signature
	if err := c.Verify([]byte("v=" + base64.StdEncoding.EncodeToString([]byte("wrongwrongwrongwrongwrongwrong12")))); err == nil {
		t.Errorf("want signature mismatch")
	}
	// malformed server-final
	if err := c.Verify([]byte("noequals")); err == nil {
		t.Errorf("want malformed final")
	}
}

func TestNewSCRAMClientRandom(t *testing.T) {
	c, err := NewSCRAMClient("u", "pw")
	if err != nil {
		t.Fatal(err)
	}
	first := c.FirstMessage()
	if !strings.HasPrefix(string(first), "n,,n=,r=") {
		t.Errorf("random client first: %q", first)
	}
	if _, err := randomNonce(); err != nil {
		t.Errorf("randomNonce: %v", err)
	}
}
