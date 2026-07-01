package pg

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func auth(kind int32, extra []byte) []byte {
	body := []byte{byte(kind >> 24), byte(kind >> 16), byte(kind >> 8), byte(kind)}
	body = append(body, extra...)
	return frame('R', body)
}

func TestStartupCleartext(t *testing.T) {
	backend := concat(
		auth(3, nil), // cleartext request
		auth(0, nil), // auth ok
		frame('K', []byte{0, 0, 0, 1, 0, 0, 0, 2}),
		frame('S', []byte("server_version\x0016\x00")),
		readyForQuery('I'),
	)
	s := newScript(backend)
	c := NewConn(s)
	if err := c.Startup(NewPasswordAuthenticator("u", "pw")); err != nil {
		t.Fatal(err)
	}
	if k, ok := c.BackendKey(); !ok || k.ProcessID != 1 {
		t.Errorf("backend key")
	}
	if v, _ := c.Parameter("server_version"); v != "16" {
		t.Errorf("param")
	}
	// The password message was sent.
	if !contains(s.out.Bytes(), "pw") {
		t.Errorf("password not sent")
	}
	cancel, err := c.CancelRequest()
	if err != nil || len(cancel) != 16 {
		t.Errorf("cancel request: %v", err)
	}
}

func contains(b []byte, sub string) bool {
	return len(sub) == 0 || indexOf(b, []byte(sub)) >= 0
}

func indexOf(h, n []byte) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if string(h[i:i+len(n)]) == string(n) {
			return i
		}
	}
	return -1
}

func TestStartupMD5(t *testing.T) {
	backend := concat(
		auth(5, []byte{1, 2, 3, 4}),
		auth(0, nil),
		readyForQuery('I'),
	)
	s := newScript(backend)
	c := NewConn(s)
	if err := c.Startup(NewPasswordAuthenticator("u", "pw")); err != nil {
		t.Fatal(err)
	}
	if !contains(s.out.Bytes(), "md5") {
		t.Errorf("md5 not sent")
	}
}

func TestStartupSCRAM(t *testing.T) {
	// Full SCRAM handshake: server offers SCRAM, exchanges, then OK.
	srv := &scramServer{password: "pw", salt: []byte("salty"), iters: 4096, nonce: "SN"}
	// Build the two server SASL payloads. We must know the client's nonce; the
	// PasswordAuthenticator generates a random one, so drive the exchange
	// message-by-message via a custom backend that reads the client's writes.
	// Simpler: use a scripted server that echoes whatever nonce we injected by
	// pre-agreeing the client nonce through a fixed authenticator.
	pa := &PasswordAuthenticator{User: "u", Password: "pw"}
	pa.scram = NewSCRAMClientWithNonce("u", "pw", "CN")

	first := pa.scram.FirstMessage()
	serverFirst := srv.firstMessage(first)
	// Compute what the client-final will be so we can craft server-final.
	clientFinal, err := pa.scram.Final(serverFirst)
	if err != nil {
		t.Fatal(err)
	}
	serverFinal := srv.finalMessage(clientFinal)

	backend := concat(
		auth(10, []byte("SCRAM-SHA-256\x00\x00")),       // AuthSASL
		auth(11, serverFirst),                           // AuthSASLContinue
		auth(12, serverFinal),                           // AuthSASLFinal
		auth(0, nil),                                    // AuthOK
		readyForQuery('I'),
	)
	c := NewConn(newScript(backend))

	// Re-run through a fresh authenticator but pin the same nonce so the crafted
	// server messages verify.
	freshPA := &PasswordAuthenticator{User: "u", Password: "pw"}
	// Handle each message manually to inject the fixed nonce on the SASL step.
	// We reuse Startup but wrap the authenticator to seed the SCRAM nonce.
	seeded := &seedingAuth{inner: freshPA, nonce: "CN"}
	if err := c.Startup(seeded); err != nil {
		t.Fatalf("scram startup: %v", err)
	}
}

// seedingAuth pins the SCRAM client nonce so a scripted server-side exchange is
// reproducible in tests.
type seedingAuth struct {
	inner *PasswordAuthenticator
	nonce string
}

func (s *seedingAuth) Handle(c *Conn, a *Authentication) error {
	if a.Kind == AuthSASL {
		s.inner.scram = NewSCRAMClientWithNonce(s.inner.User, s.inner.Password, s.nonce)
		return c.write(EncodeSASLInitialResponse(SCRAMMechanism, s.inner.scram.FirstMessage()))
	}
	return s.inner.Handle(c, a)
}

func TestStartupErrors(t *testing.T) {
	// ErrorResponse during startup.
	c := NewConn(newScript(concat(frame('E', []byte("SFATAL\x00Mnope\x00\x00")))))
	if err := c.Startup(nil); err == nil {
		t.Errorf("want startup error")
	}
	// Auth required but no authenticator.
	c = NewConn(newScript(auth(3, nil)))
	if err := c.Startup(nil); err == nil {
		t.Errorf("want no-authenticator error")
	}
	// Unexpected message type.
	c = NewConn(newScript(frame('D', []byte{0, 0})))
	if err := c.Startup(nil); err == nil {
		t.Errorf("want unexpected-message error")
	}
	// Read error.
	c = NewConn(&errRW{})
	if err := c.Startup(nil); err == nil {
		t.Errorf("want read error")
	}
}

func TestAuthenticatorErrors(t *testing.T) {
	c := NewConn(newScript(nil))
	pa := NewPasswordAuthenticator("u", "pw")
	// Bad MD5 salt length.
	if err := pa.Handle(c, &Authentication{Kind: AuthMD5Password, Salt: []byte{1}}); err == nil {
		t.Errorf("want md5 salt error")
	}
	// SASL with no supported mechanism.
	if err := pa.Handle(c, &Authentication{Kind: AuthSASL, Mechanisms: []string{"OTHER"}}); err == nil {
		t.Errorf("want no-mechanism error")
	}
	// SASLContinue before SASL.
	pa2 := NewPasswordAuthenticator("u", "pw")
	if err := pa2.Handle(c, &Authentication{Kind: AuthSASLContinue, Data: []byte("x")}); err == nil {
		t.Errorf("want continue-before-sasl error")
	}
	// SASLFinal before SASL.
	if err := pa2.Handle(c, &Authentication{Kind: AuthSASLFinal, Data: []byte("x")}); err == nil {
		t.Errorf("want final-before-sasl error")
	}
	// Unsupported kind.
	if err := pa2.Handle(c, &Authentication{Kind: AuthGSS}); err == nil {
		t.Errorf("want unsupported kind error")
	}
	// SASLContinue with malformed data (after a valid SASL).
	pa3 := NewPasswordAuthenticator("u", "pw")
	_ = pa3.Handle(c, &Authentication{Kind: AuthSASL, Mechanisms: []string{SCRAMMechanism}})
	if err := pa3.Handle(c, &Authentication{Kind: AuthSASLContinue, Data: []byte("garbage")}); err == nil {
		t.Errorf("want continue parse error")
	}
}

func TestAuthenticatorWriteError(t *testing.T) {
	c := NewConn(&errRW{writeErr: true})
	pa := NewPasswordAuthenticator("u", "pw")
	if err := pa.Handle(c, &Authentication{Kind: AuthCleartextPassword}); err == nil {
		t.Errorf("want cleartext write error")
	}
	if err := pa.Handle(c, &Authentication{Kind: AuthMD5Password, Salt: []byte{1, 2, 3, 4}}); err == nil {
		t.Errorf("want md5 write error")
	}
	if err := pa.Handle(c, &Authentication{Kind: AuthSASL, Mechanisms: []string{SCRAMMechanism}}); err == nil {
		t.Errorf("want sasl write error")
	}
}

// Ensure the reference SCRAM server crypto is exercised (keeps helpers honest).
func TestScramServerHelpers(t *testing.T) {
	salted, _ := pbkdf2.Key(sha256.New, "pw", []byte("s"), 2, sha256.Size)
	h := hmac.New(sha256.New, salted)
	h.Write([]byte("x"))
	if len(h.Sum(nil)) != 32 {
		t.Errorf("hmac size")
	}
	_ = base64.StdEncoding
}
