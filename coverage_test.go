package pg

import (
	"crypto/sha256"
	"errors"
	"hash"
	"testing"
)

// TestReadBufGuards exercises the already-failed early returns of the buffer
// primitives (a decoder that keeps reading after an error must be a no-op).
func TestReadBufGuards(t *testing.T) {
	r := &readBuf{err: errShort}
	if r.byte() != 0 || r.int16() != 0 || r.int32() != 0 || r.string() != "" || r.next(1) != nil {
		t.Errorf("failed buffer should return zero values")
	}
	// next with negative length sets errShort.
	r2 := &readBuf{b: []byte{1, 2, 3}}
	if r2.next(-1) != nil || r2.err != errShort {
		t.Errorf("negative next should fail")
	}
}

// TestAuthCryptoSeamErrors injects failures into the crypto seams.
func TestAuthCryptoSeamErrors(t *testing.T) {
	// randRead failure -> NewSCRAMClient and randomNonce error.
	origRand := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() { randRead = origRand }()
	if _, err := NewSCRAMClient("u", "pw"); err == nil {
		t.Errorf("want NewSCRAMClient rand error")
	}
	if _, err := randomNonce(); err == nil {
		t.Errorf("want randomNonce error")
	}
	// PasswordAuthenticator.Handle(AuthSASL) also propagates the rand error.
	pa := NewPasswordAuthenticator("u", "pw")
	c := NewConn(newScript(nil))
	if err := pa.Handle(c, &Authentication{Kind: AuthSASL, Mechanisms: []string{SCRAMMechanism}}); err == nil {
		t.Errorf("want SASL rand error")
	}
}

func TestPBKDF2SeamError(t *testing.T) {
	orig := pbkdf2Key
	pbkdf2Key = func(func() hash.Hash, string, []byte, int, int) ([]byte, error) {
		return nil, errors.New("pbkdf2 boom")
	}
	defer func() { pbkdf2Key = orig }()
	c := NewSCRAMClientWithNonce("u", "pw", "CN")
	c.FirstMessage()
	sf := "r=CN9,s=c2FsdA==,i=4096" // valid-looking server-first
	if _, err := c.Final([]byte(sf)); err == nil {
		t.Errorf("want pbkdf2 error")
	}
	_ = sha256.New
}
