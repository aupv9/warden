// Package smtptest is a small in-process SMTP server for tests: EHLO,
// optional STARTTLS (with a certificate generated at start), AUTH PLAIN,
// MAIL/RCPT/DATA. It records every accepted message.
package smtptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// Parsed is a decoded message: headers and the text and HTML parts.
type Parsed struct {
	Header mail.Header
	Text   string
	HTML   string
}

// Parse decodes a multipart/alternative message (quoted-printable parts).
func Parse(raw string) (Parsed, error) {
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return Parsed{}, err
	}
	out := Parsed{Header: m.Header}
	_, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil {
		return out, err
	}
	r := multipart.NewReader(m.Body, params["boundary"])
	for {
		p, err := r.NextPart() // decodes quoted-printable transparently
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		body, err := io.ReadAll(p)
		if err != nil {
			return out, err
		}
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") {
			out.HTML = string(body)
		} else {
			out.Text = string(body)
		}
	}
}

// Message is one accepted email.
type Message struct {
	From string
	To   []string
	Data string
	TLS  bool
	Auth string // username, if the client authenticated
}

type Options struct {
	// STARTTLS offers STARTTLS with a self-signed certificate for 127.0.0.1.
	STARTTLS bool
	// ImplicitTLS speaks TLS from the first byte.
	ImplicitTLS bool
	// Username/Password: require AUTH PLAIN with these.
	Username, Password string
	// RejectRcpt answers RCPT with 550 for these addresses.
	RejectRcpt []string
}

type Server struct {
	ln   net.Listener
	opts Options
	tls  *tls.Config
	pool *x509.CertPool

	mu   sync.Mutex
	msgs []Message
	wg   sync.WaitGroup
}

// Start listens on 127.0.0.1 on a free port.
func Start(opts Options) (*Server, error) {
	s := &Server{opts: opts}
	if opts.STARTTLS || opts.ImplicitTLS {
		if err := s.makeCert(); err != nil {
			return nil, err
		}
	}
	var err error
	if opts.ImplicitTLS {
		s.ln, err = tls.Listen("tcp", "127.0.0.1:0", s.tls)
	} else {
		s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return nil, err
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

func (s *Server) makeCert() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtptest"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	s.pool = x509.NewCertPool()
	s.pool.AddCert(cert)
	s.tls = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	return nil
}

// Addr returns host and port.
func (s *Server) Addr() (string, int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// ClientTLS trusts the server's certificate.
func (s *Server) ClientTLS() *tls.Config {
	return &tls.Config{RootCAs: s.pool, MinVersion: tls.VersionTLS12}
}

// Messages returns the accepted messages.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.msgs...)
}

// Close stops the server and waits for its connections.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.wg.Wait()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			s.session(c)
		}()
	}
}

func (s *Server) session(c net.Conn) {
	_, isTLS := c.(*tls.Conn)
	tp := textproto.NewConn(c)
	reply := func(code int, msg string) { _ = tp.PrintfLine("%d %s", code, msg) }
	reply(220, "smtptest ready")
	var msg Message
	msg.TLS = isTLS
	authed := s.opts.Username == ""
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			lines := []string{"250-smtptest"}
			if s.opts.STARTTLS && !msg.TLS {
				lines = append(lines, "250-STARTTLS")
			}
			if s.opts.Username != "" {
				lines = append(lines, "250-AUTH PLAIN")
			}
			lines = append(lines, "250 8BITMIME")
			for _, l := range lines {
				_ = tp.PrintfLine("%s", l)
			}
		case "STARTTLS":
			if !s.opts.STARTTLS || msg.TLS {
				reply(502, "not supported")
				continue
			}
			reply(220, "go ahead")
			tc := tls.Server(c, s.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, msg.TLS = tc, true
			tp = textproto.NewConn(tc)
			reply = func(code int, m string) { _ = tp.PrintfLine("%d %s", code, m) }
		case "AUTH":
			mech, b64, _ := strings.Cut(arg, " ")
			raw, err := base64.StdEncoding.DecodeString(b64)
			parts := strings.Split(string(raw), "\x00")
			if !strings.EqualFold(mech, "PLAIN") || err != nil || len(parts) != 3 ||
				parts[1] != s.opts.Username || parts[2] != s.opts.Password {
				reply(535, "authentication failed")
				continue
			}
			authed, msg.Auth = true, parts[1]
			reply(235, "ok")
		case "MAIL":
			if !authed {
				reply(530, "authentication required")
				continue
			}
			msg.From = addr(arg)
			reply(250, "ok")
		case "RCPT":
			to := addr(arg)
			rejected := false
			for _, r := range s.opts.RejectRcpt {
				if strings.EqualFold(r, to) {
					rejected = true
				}
			}
			if rejected {
				reply(550, "no such user")
				continue
			}
			msg.To = append(msg.To, to)
			reply(250, "ok")
		case "DATA":
			reply(354, "end with .")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			msg.Data = string(data)
			s.mu.Lock()
			s.msgs = append(s.msgs, msg)
			s.mu.Unlock()
			msg = Message{TLS: msg.TLS, Auth: msg.Auth}
			reply(250, "queued")
		case "RSET", "NOOP":
			reply(250, "ok")
		case "QUIT":
			reply(221, "bye")
			return
		default:
			reply(502, "unknown command")
		}
	}
}

func addr(arg string) string {
	_, v, _ := strings.Cut(arg, ":")
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = v[:i]
	}
	return strings.Trim(v, "<>")
}
