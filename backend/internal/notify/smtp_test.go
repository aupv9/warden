package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/notify/smtptest"
)

var testMail = Mail{To: "dev@example.com", Subject: "[Warden] WEB-1 assigned to you", Text: "text", HTML: "<p>html</p>"}

func start(t *testing.T, o smtptest.Options) (*smtptest.Server, string, int) {
	t.Helper()
	s, err := smtptest.Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	host, port := s.Addr()
	return s, host, port
}

func sender(t *testing.T, cfg SMTPConfig) *SMTPSender {
	t.Helper()
	s, err := NewSMTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSMTPPlainToLoopback(t *testing.T) {
	srv, host, port := start(t, smtptest.Options{})
	if err := sender(t, SMTPConfig{Host: host, Port: port, From: "warden@example.com"}).Send(context.Background(), testMail); err != nil {
		t.Fatal(err)
	}
	m := srv.Messages()
	if len(m) != 1 || m[0].From != "warden@example.com" || m[0].To[0] != "dev@example.com" || m[0].TLS {
		t.Fatalf("%+v", m)
	}
	if p, err := smtptest.Parse(m[0].Data); err != nil || p.Text != "text" || p.HTML != "<p>html</p>" {
		t.Fatal(p, err)
	}
}

func TestSMTPStartTLSAndAuth(t *testing.T) {
	srv, host, port := start(t, smtptest.Options{STARTTLS: true, Username: "u", Password: "p"})
	s := sender(t, SMTPConfig{Host: host, Port: port, From: "warden@example.com", Username: "u", Password: "p", TLSConfig: srv.ClientTLS()})
	if err := s.Send(context.Background(), testMail); err != nil {
		t.Fatal(err)
	}
	if m := srv.Messages(); len(m) != 1 || !m[0].TLS || m[0].Auth != "u" {
		t.Fatalf("%+v", m)
	}
	bad := sender(t, SMTPConfig{Host: host, Port: port, From: "warden@example.com", Username: "u", Password: "wrong", TLSConfig: srv.ClientTLS()})
	if err := bad.Send(context.Background(), testMail); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatal(err)
	}
	// Without trusting the certificate, STARTTLS fails closed.
	untrusted := sender(t, SMTPConfig{Host: host, Port: port, From: "warden@example.com"})
	if err := untrusted.Send(context.Background(), testMail); err == nil || !strings.Contains(err.Error(), "starttls") {
		t.Fatal(err)
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	srv, host, port := start(t, smtptest.Options{ImplicitTLS: true})
	s := sender(t, SMTPConfig{Host: host, Port: port, From: "warden@example.com", ImplicitTLS: true, TLSConfig: srv.ClientTLS()})
	if err := s.Send(context.Background(), testMail); err != nil {
		t.Fatal(err)
	}
	if m := srv.Messages(); len(m) != 1 || !m[0].TLS {
		t.Fatalf("%+v", m)
	}
}

// A non-local server that doesn't offer STARTTLS gets neither mail nor
// credentials; one that does is used over TLS.
func TestSMTPRequiresTLSUnlessLoopback(t *testing.T) {
	srv, host, port := start(t, smtptest.Options{Username: "u", Password: "p"})
	s := sender(t, SMTPConfig{Host: "mail.example.test", Port: 25, From: "warden@example.com", Username: "u", Password: "p"})
	s.dialAddr = net.JoinHostPort(host, strconv.Itoa(port))
	if err := s.Send(context.Background(), testMail); !errors.Is(err, ErrNoTLS) {
		t.Fatal(err)
	}
	if len(srv.Messages()) != 0 {
		t.Fatal("mail sent in clear text")
	}

	tlsSrv, host, port := start(t, smtptest.Options{STARTTLS: true})
	cfg := tlsSrv.ClientTLS()
	cfg.ServerName = "localhost" // the test certificate's name
	s = sender(t, SMTPConfig{Host: "mail.example.test", Port: 25, From: "warden@example.com", TLSConfig: cfg})
	s.dialAddr = net.JoinHostPort(host, strconv.Itoa(port))
	if err := s.Send(context.Background(), testMail); err != nil {
		t.Fatal(err)
	}
	if m := tlsSrv.Messages(); len(m) != 1 || !m[0].TLS {
		t.Fatalf("%+v", m)
	}
}

func TestSMTPFailures(t *testing.T) {
	srv, host, port := start(t, smtptest.Options{RejectRcpt: []string{"gone@example.com"}})
	s := sender(t, SMTPConfig{Host: host, Port: port, From: "warden@example.com"})
	err := s.Send(context.Background(), Mail{To: "gone@example.com", Subject: "s"})
	var ce *ConnError
	if err == nil || errors.As(err, &ce) {
		t.Fatal("a rejected recipient is not a connection error", err)
	}
	if err := s.Send(context.Background(), Mail{To: "x\r\nBcc: y@example.com", Subject: "s"}); !errors.Is(err, ErrHeaderInjection) {
		t.Fatal(err)
	}
	srv.Close()
	if err := s.Send(context.Background(), testMail); !errors.As(err, &ce) || ce.Unwrap() == nil || ce.Error() == "" {
		t.Fatal("refused connection should be a ConnError", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Send(ctx, testMail); err == nil {
		t.Fatal("sent with a cancelled context")
	}
}

func TestNewSMTPValidates(t *testing.T) {
	for _, cfg := range []SMTPConfig{
		{Port: 25, From: "a@b.c"},
		{Host: "h\r\n", Port: 25, From: "a@b.c"},
		{Host: "h", Port: 0, From: "a@b.c"},
		{Host: "h", Port: 25, From: "a@b.c\r\nBcc: x"},
		{Host: "h", Port: 25, From: "nope"},
		{Host: "h", Port: 25, From: "a@b.c", Username: "u\n"},
	} {
		if _, err := NewSMTP(cfg); err == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
	s := sender(t, SMTPConfig{Host: "h", Port: 25, From: "a@b.c", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}})
	if c := s.tlsConfig(); c.ServerName != "h" || c.MinVersion != tls.VersionTLS13 {
		t.Fatal(c)
	}
	for host, want := range map[string]bool{"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "::1": true, "10.0.0.1": false, "mail.example.com": false} {
		if IsLoopback(host) != want {
			t.Error(host)
		}
	}
}
