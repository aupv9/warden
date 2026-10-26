package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Sender delivers one email.
type Sender interface {
	Send(ctx context.Context, m Mail) error
}

// SMTPConfig configures SMTPSender.
type SMTPConfig struct {
	Host string
	Port int
	From string
	// Username/Password enable AUTH PLAIN (only ever sent over TLS, or to localhost).
	Username string
	Password string
	// ImplicitTLS connects with TLS from the start (port 465) instead of STARTTLS.
	ImplicitTLS bool
	// Timeout bounds one delivery (connect to QUIT). Default 30s.
	Timeout time.Duration
	// TLSConfig overrides the TLS settings (tests). ServerName defaults to Host.
	TLSConfig *tls.Config
}

// SMTPSender sends mail with net/smtp, one connection per message.
//
// TLS: STARTTLS is used whenever the server offers it, and is required unless
// the host is a loopback name (a local relay or Mailpit in development);
// without it a non-local server is refused rather than sent credentials or
// mail in clear text.
type SMTPSender struct {
	cfg SMTPConfig
	// dialAddr overrides where to connect while keeping cfg.Host as the TLS
	// and loopback name (tests).
	dialAddr string
}

// NewSMTP validates cfg and returns a sender.
func NewSMTP(cfg SMTPConfig) (*SMTPSender, error) {
	if cfg.Host == "" || strings.ContainsAny(cfg.Host, "\r\n/ ") {
		return nil, errors.New("notify: smtp host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, errors.New("notify: smtp port must be 1-65535")
	}
	if strings.ContainsAny(cfg.From, "\r\n") {
		return nil, ErrHeaderInjection
	}
	if _, err := mail.ParseAddress(cfg.From); err != nil {
		return nil, errors.New("notify: smtp from must be an email address")
	}
	if strings.ContainsAny(cfg.Username, "\r\n") {
		return nil, ErrHeaderInjection
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &SMTPSender{cfg: cfg}, nil
}

// IsLoopback reports whether host names this machine.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *SMTPSender) tlsConfig() *tls.Config {
	if s.cfg.TLSConfig != nil {
		c := s.cfg.TLSConfig.Clone()
		if c.ServerName == "" {
			c.ServerName = s.cfg.Host
		}
		return c
	}
	return &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}
}

// ErrNoTLS: the server didn't offer STARTTLS and isn't local.
var ErrNoTLS = errors.New("notify: smtp server does not offer STARTTLS")

// ConnError marks failures to reach the server at all; the dispatcher stops
// sending for this run instead of waiting on every queued message.
type ConnError struct{ Err error }

func (e *ConnError) Error() string { return "smtp connect: " + e.Err.Error() }
func (e *ConnError) Unwrap() error { return e.Err }

func (s *SMTPSender) Send(ctx context.Context, m Mail) error {
	msg, err := Build(s.cfg.From, m, time.Now())
	if err != nil {
		return err
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return errors.New("notify: invalid recipient address")
	}
	from, _ := mail.ParseAddress(s.cfg.From)

	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	if s.dialAddr != "" {
		addr = s.dialAddr
	}
	d := &net.Dialer{}
	var conn net.Conn
	if s.cfg.ImplicitTLS {
		conn, err = (&tls.Dialer{NetDialer: d, Config: s.tlsConfig()}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return &ConnError{Err: err}
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	// Unblock the protocol exchange if the context is cancelled early.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return &ConnError{Err: err}
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if !s.cfg.ImplicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(s.tlsConfig()); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		} else if !IsLoopback(s.cfg.Host) {
			return ErrNoTLS
		}
	}
	if s.cfg.Username != "" {
		// PlainAuth itself refuses to send credentials without TLS unless the
		// host is localhost.
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
