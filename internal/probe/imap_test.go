package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
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

// TestCertVerdictNamesTheMailcowExample is the lesson from a staging run in
// which the check reported "certificate expired on 2019-11-28" while ACME had
// just renewed successfully. The verdict was right — postfix and dovecot were
// still serving the example pair mailcow ships — but nothing in it said so, and
// the probe was suspected instead of the deployment.
//
// The fixture is the certificate itself, taken from
// mailcow-dockerized/data/assets/ssl-example/cert.pem, rather than one shaped
// like it: a generated stand-in was strictly self-signed, while the real one is
// signed by a separate "O=mailcow" issuer. Testing against the friendlier shape
// would have proved a message the field never produces.
//
// If this fails, the log again forces the operator to run openssl by hand to
// learn which certificate the probe even looked at.
func TestCertVerdictNamesTheMailcowExample(t *testing.T) {
	leaf := loadTestCertificate(t, "testdata/mailcow-example-cert.pem")

	res := certExpiry(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}},
		7, "dovecot-cert: dovecot-mailcow:993")

	if res.Status != health.StatusCritical {
		t.Fatalf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	// The subject says which host it claims to be, the issuer says who vouched
	// for it. Either one alone identifies this as mailcow's example pair rather
	// than a certificate ACME wrote.
	for _, want := range []string{"mail.example.org", "O=mailcow", "2019-11-28"} {
		if !strings.Contains(res.Message, want) {
			t.Errorf("message = %q, want it to mention %q", res.Message, want)
		}
	}
}

// The same identity has to survive the whole probe, not just the helper: a
// verdict assembled correctly and then discarded on the way out of Run would
// pass the test above and still reach the log without it.
func TestCertVerdictSurvivesTheProbe(t *testing.T) {
	cert := selfSigned(t, time.Date(2016, 12, 13, 10, 11, 0, 0, time.UTC),
		time.Date(2019, 11, 28, 10, 11, 0, 0, time.UTC))
	host, port := tlsBannerServer(t, cert, "* OK ready\r\n")

	res := runProbe(t, NewIMAP("dovecot-cert", Static(host), port,
		IMAPOptions{TLS: true, MinCertDays: 7}))

	if res.Status != health.StatusCritical {
		t.Fatalf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	for _, want := range []string{"mail.example.org", "2019-11-28"} {
		if !strings.Contains(res.Message, want) {
			t.Errorf("message = %q, want it to mention %q", res.Message, want)
		}
	}
}

// loadTestCertificate reads a PEM certificate from testdata.
func loadTestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return leaf
}

// A certificate from a real CA must name that CA rather than be called
// self-signed, or the distinction the previous test relies on is worthless.
func TestCertVerdictNamesTheIssuer(t *testing.T) {
	leaf := issuedLeaf(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	res := certExpiry(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}},
		7, "postfix-cert: postfix-mailcow:589")

	if res.Status != health.StatusOK {
		t.Fatalf("status = %v (%s), want OK", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, `issuer "CN=Example CA`) {
		t.Errorf("message = %q, want it to name the issuing CA", res.Message)
	}
	if strings.Contains(res.Message, "self-signed") {
		t.Errorf("message = %q calls a CA-issued certificate self-signed", res.Message)
	}
}

// issuedLeaf returns a leaf signed by a separate CA certificate, so that issuer
// and subject genuinely differ.
func issuedLeaf(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the CA key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Example CA X1", Organization: []string{"Example"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing the CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the leaf key: %v", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "mail.example.org"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"mail.example.org"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing the leaf certificate: %v", err)
	}
	return leaf
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
