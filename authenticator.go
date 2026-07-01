package pg

import "fmt"

// Authenticator responds to an Authentication challenge during Startup, writing
// the appropriate frontend message(s) to the connection. It is a seam: a host
// can plug in its own (GSS/SSPI) scheme; PasswordAuthenticator covers the
// cleartext, MD5, and SCRAM-SHA-256 methods that need only pure crypto.
type Authenticator interface {
	// Handle reacts to a single Authentication message, writing any response.
	// For SCRAM it is invoked once per challenge (SASL, SASLContinue).
	Handle(c *Conn, a *Authentication) error
}

// PasswordAuthenticator answers cleartext, MD5, and SCRAM-SHA-256 challenges with
// the given username and password. It keeps the SCRAM exchange state across the
// SASL / SASLContinue / SASLFinal round trips.
type PasswordAuthenticator struct {
	User     string
	Password string

	scram *SCRAMClient
}

// NewPasswordAuthenticator builds a PasswordAuthenticator.
func NewPasswordAuthenticator(user, password string) *PasswordAuthenticator {
	return &PasswordAuthenticator{User: user, Password: password}
}

// Handle dispatches on the challenge kind.
func (p *PasswordAuthenticator) Handle(c *Conn, a *Authentication) error {
	switch a.Kind {
	case AuthCleartextPassword:
		return c.write(EncodePassword(p.Password))
	case AuthMD5Password:
		if len(a.Salt) != 4 {
			return fmt.Errorf("pg: MD5 auth salt must be 4 bytes, got %d", len(a.Salt))
		}
		return c.write(EncodePassword(MD5Password(p.User, p.Password, a.Salt)))
	case AuthSASL:
		if !containsMechanism(a.Mechanisms, SCRAMMechanism) {
			return fmt.Errorf("pg: no supported SASL mechanism in %v", a.Mechanisms)
		}
		sc, err := NewSCRAMClient(p.User, p.Password)
		if err != nil {
			return err
		}
		p.scram = sc
		return c.write(EncodeSASLInitialResponse(SCRAMMechanism, sc.FirstMessage()))
	case AuthSASLContinue:
		if p.scram == nil {
			return fmt.Errorf("pg: SASLContinue before SASL")
		}
		final, err := p.scram.Final(a.Data)
		if err != nil {
			return err
		}
		return c.write(EncodeSASLResponse(final))
	case AuthSASLFinal:
		if p.scram == nil {
			return fmt.Errorf("pg: SASLFinal before SASL")
		}
		return p.scram.Verify(a.Data)
	}
	return fmt.Errorf("pg: unsupported authentication kind %d", a.Kind)
}

func containsMechanism(list []string, want string) bool {
	for _, m := range list {
		if m == want {
			return true
		}
	}
	return false
}
