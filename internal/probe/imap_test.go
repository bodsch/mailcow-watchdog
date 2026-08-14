package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// selfSigned builds a certificate valid for the given window. The probes never
// verify the chain — they connect to container IPs while the certificate names
// the public hostname — so a self-signed leaf is exactly what they see in
// production too.
func selfSigned(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.example.org"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"mail.example.org"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsBannerServer serves an implicit-TLS listener that greets and hangs up.
func tlsBannerServer(t *testing.T, cert tls.Certificate, banner string) (string, int) {
	t.Helper()

	return listenLocal(t, func(conn net.Conn) {
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()
		_, _ = io.WriteString(tlsConn, banner)
	})
}

func TestIMAPGreeting(t *testing.T) {
	host, port := bannerServer(t, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n")

	res := runProbe(t, NewIMAP("dovecot", Static(host), port, IMAPOptions{Expect: "OK "}))
	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

func TestIMAPWrongGreetingIsCritical(t *testing.T) {
	host, port := bannerServer(t, "* BYE too many connections\r\n")

	res := runProbe(t, NewIMAP("dovecot", Static(host), port, IMAPOptions{Expect: "OK "}))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}

func TestIMAPOverTLS(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	host, port := tlsBannerServer(t, cert, "* OK Dovecot ready.\r\n")

	res := runProbe(t, NewIMAP("dovecot", Static(host), port, IMAPOptions{TLS: true}))
	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

// The certificate check is the -D flag of check_imap: fewer than the configured
// number of days left is CRITICAL.
func TestIMAPCertificateExpiry(t *testing.T) {
	tests := []struct {
		name     string
		validFor time.Duration
		want     health.Status
	}{
		{"plenty of time", 90 * 24 * time.Hour, health.StatusOK},
		{"exactly at the limit", 8 * 24 * time.Hour, health.StatusOK},
		{"about to expire", 3 * 24 * time.Hour, health.StatusCritical},
		{"already expired", -time.Hour, health.StatusCritical},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := selfSigned(t, time.Now().Add(-time.Hour), time.Now().Add(tc.validFor))
			host, port := tlsBannerServer(t, cert, "* OK ready\r\n")

			res := runProbe(t, NewIMAP("cert", Static(host), port,
				IMAPOptions{TLS: true, MinCertDays: 7}))
			if res.Status != tc.want {
				t.Errorf("status = %v (%s), want %v", res.Status, res.Message, tc.want)
			}
		})
	}
}

func TestIMAPCertificateCheckNeedsTLS(t *testing.T) {
	host, port := bannerServer(t, "* OK ready\r\n")

	res := runProbe(t, NewIMAP("cert", Static(host), port, IMAPOptions{MinCertDays: 7}))
	if res.Status != health.StatusUnknown {
		t.Errorf("status = %v (%s), want UNKNOWN", res.Status, res.Message)
	}
}

func TestIMAPDefaultExpectation(t *testing.T) {
	p := NewIMAP("dovecot", Static("x"), 143, IMAPOptions{})
	if p.opts.Expect != "* OK" {
		t.Errorf("default Expect = %q, want %q", p.opts.Expect, "* OK")
	}
}

func TestIMAPUnreachableIsCritical(t *testing.T) {
	host, port := closedPort(t)

	res := runProbe(t, NewIMAP("dovecot", Static(host), port, IMAPOptions{}))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}

// certExpiry is shared by the SMTP and IMAP certificate checks, so it is worth
// pinning down on its own.
func TestCertExpiry(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		state   tls.ConnectionState
		want    health.Status
		mention string
	}{
		{
			name:    "no certificate",
			state:   tls.ConnectionState{},
			want:    health.StatusCritical,
			mention: "no certificate",
		},
		{
			name:    "not yet valid",
			state:   stateWith(t, now.Add(24*time.Hour), now.Add(48*time.Hour)),
			want:    health.StatusCritical,
			mention: "not valid before",
		},
		{
			name:    "expired",
			state:   stateWith(t, now.Add(-48*time.Hour), now.Add(-time.Minute)),
			want:    health.StatusCritical,
			mention: "expired on",
		},
		{
			name:    "expiring soon",
			state:   stateWith(t, now.Add(-time.Hour), now.Add(2*24*time.Hour)),
			want:    health.StatusCritical,
			mention: "expires in",
		},
		{
			name:  "healthy",
			state: stateWith(t, now.Add(-time.Hour), now.Add(30*24*time.Hour)),
			want:  health.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := certExpiry(tc.state, 7, "cert: mail.example.org:993")
			if res.Status != tc.want {
				t.Errorf("status = %v (%s), want %v", res.Status, res.Message, tc.want)
			}
			if tc.mention != "" && !strings.Contains(res.Message, tc.mention) {
				t.Errorf("message = %q, want it to mention %q", res.Message, tc.mention)
			}
		})
	}
}

// stateWith builds a ConnectionState carrying a single leaf certificate.
func stateWith(t *testing.T, notBefore, notAfter time.Time) tls.ConnectionState {
	t.Helper()

	cert := selfSigned(t, notBefore, notAfter)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
}
