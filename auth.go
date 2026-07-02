package pg

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// randRead and pbkdf2Key are indirection seams over crypto/rand and
// crypto/pbkdf2 so their (otherwise unreachable) error paths are exercisable in
// tests. Production always uses the standard-library implementations.
var (
	randRead  = rand.Read
	pbkdf2Key = func(h func() hash.Hash, password string, salt []byte, iter, keyLen int) ([]byte, error) {
		return pbkdf2.Key(h, password, salt, iter, keyLen)
	}
)

// This file implements the pure-crypto side of PostgreSQL authentication: the
// MD5 password digest and the SCRAM-SHA-256 (RFC 5802 / RFC 7677) client
// exchange. Both are pure functions of their inputs (the SCRAM client nonce is
// injectable for deterministic tests), so no socket or server is involved.

// MD5Password computes the "md5"+hex digest PostgreSQL's AuthenticationMD5Password
// expects: md5(md5(password + username) + salt), where salt is the 4-byte value
// from the Authentication message. The result is the string sent in a
// PasswordMessage.
func MD5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...))
	return "md5" + hex.EncodeToString(outer[:])
}

// SCRAMMechanism is the name of the SCRAM mechanism this package implements.
const SCRAMMechanism = "SCRAM-SHA-256"

// SCRAMClient drives the client half of a SCRAM-SHA-256 exchange. Construct it
// with NewSCRAMClient, send FirstMessage in a SASLInitialResponse, feed the
// server-first message to Final to obtain the client-final message
// (SASLResponse), then verify the server-final message with Verify.
type SCRAMClient struct {
	user        string
	password    string
	clientNonce string
	firstBare   string // client-first-message-bare (without the gs2 header)
	serverSig   []byte // computed in Final, checked in Verify
}

// gs2Header is the channel-binding-unsupported GS2 header ("n,,").
const gs2Header = "n,,"

// NewSCRAMClient builds a client with a random 24-byte base64 client nonce. Use
// NewSCRAMClientWithNonce to pin the nonce for deterministic tests.
func NewSCRAMClient(user, password string) (*SCRAMClient, error) {
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	return NewSCRAMClientWithNonce(user, password, nonce), nil
}

// NewSCRAMClientWithNonce builds a client with a caller-supplied client nonce.
func NewSCRAMClientWithNonce(user, password, clientNonce string) *SCRAMClient {
	return &SCRAMClient{user: user, password: password, clientNonce: clientNonce}
}

// randomNonce returns a base64 client nonce from crypto/rand.
func randomNonce() (string, error) {
	var buf [18]byte
	if _, err := randRead(buf[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf[:]), nil
}

// FirstMessage returns the client-first message (the SASLInitialResponse payload).
// PostgreSQL always uses an empty SCRAM username (the startup "user" carries it),
// so the n= field is empty.
func (c *SCRAMClient) FirstMessage() []byte {
	c.firstBare = "n=,r=" + c.clientNonce
	return []byte(gs2Header + c.firstBare)
}

// Final consumes the server-first message and returns the client-final message
// (the SASLResponse payload). It rejects a server nonce that does not extend the
// client nonce (a MITM guard).
func (c *SCRAMClient) Final(serverFirst []byte) ([]byte, error) {
	attrs, err := parseSCRAM(string(serverFirst))
	if err != nil {
		return nil, err
	}
	serverNonce := attrs["r"]
	saltB64 := attrs["s"]
	iterStr := attrs["i"]
	if serverNonce == "" || saltB64 == "" || iterStr == "" {
		return nil, errors.New("pg: malformed SCRAM server-first message")
	}
	if !strings.HasPrefix(serverNonce, c.clientNonce) {
		return nil, errors.New("pg: SCRAM server nonce does not extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("pg: SCRAM salt: %w", err)
	}
	iters, err := strconv.Atoi(iterStr)
	if err != nil || iters <= 0 {
		return nil, errors.New("pg: SCRAM iteration count invalid")
	}

	saltedPassword, err := pbkdf2Key(sha256.New, c.password, salt, iters, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("pg: SCRAM pbkdf2: %w", err)
	}
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))

	channelBinding := "c=" + base64.StdEncoding.EncodeToString([]byte(gs2Header))
	clientFinalNoProof := channelBinding + ",r=" + serverNonce
	authMessage := c.firstBare + "," + string(serverFirst) + "," + clientFinalNoProof

	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	proof := xorBytes(clientKey, clientSignature)
	c.serverSig = hmacSHA256(serverKey, []byte(authMessage))

	final := clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(proof)
	return []byte(final), nil
}

// Verify checks the server-final message's v= signature against the value Final
// computed. It must be called after Final.
func (c *SCRAMClient) Verify(serverFinal []byte) error {
	if c.serverSig == nil {
		return errors.New("pg: SCRAM Verify called before Final")
	}
	attrs, err := parseSCRAM(string(serverFinal))
	if err != nil {
		return err
	}
	if e, ok := attrs["e"]; ok {
		return fmt.Errorf("pg: SCRAM authentication failed: %s", e)
	}
	vB64 := attrs["v"]
	if vB64 == "" {
		return errors.New("pg: SCRAM server-final missing verifier")
	}
	got, err := base64.StdEncoding.DecodeString(vB64)
	if err != nil {
		return fmt.Errorf("pg: SCRAM verifier: %w", err)
	}
	if subtle.ConstantTimeCompare(got, c.serverSig) != 1 {
		return errors.New("pg: SCRAM server signature mismatch")
	}
	return nil
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// parseSCRAM splits a comma-separated SCRAM message into its attr=value pairs.
// Values may themselves contain '=' (base64), so only the first '=' splits.
func parseSCRAM(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 1 {
			return nil, fmt.Errorf("pg: malformed SCRAM attribute %q", part)
		}
		out[part[:eq]] = part[eq+1:]
	}
	return out, nil
}
