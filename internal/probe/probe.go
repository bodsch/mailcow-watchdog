// Package probe implements the individual measurements a check performs.
//
// Each probe replaces one invocation of a Nagios plugin from the original
// watchdog.sh and reports the same four-state verdict, because the numeric exit
// code doubles as the number of error points the round costs (see package
// health). Doing this in-process removes nineteen fork/exec pairs per round and,
// more importantly, makes every probe a unit under test rather than a string of
// shell.
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// DefaultTimeout bounds a single probe. The Nagios plugins defaulted to ten
// seconds and the shell never overrode it.
const DefaultTimeout = 10 * time.Second

// Probe is one measurement against one service.
type Probe interface {
	// Name identifies the probe in logs, metrics and detail transcripts.
	Name() string
	// Run performs the measurement. It reports failures through the returned
	// Result rather than through an error, so that a check can fold every
	// outcome into its error budget uniformly.
	Run(ctx context.Context) Result
}

// Result is a probe's verdict, modelled on a Nagios plugin's exit code plus its
// single line of output.
type Result struct {
	Probe    string
	Status   health.Status
	Message  string
	Duration time.Duration
	// Points is the number of error points this result contributes to the
	// check's budget. It defaults to the Nagios exit code, which is what the
	// shell's `err_count=$(( ${err_count} + $? ))` accumulated. Probes that
	// replace a hand-written `err_count + 1` are wrapped in Cost instead.
	Points int
}

// Weight is the number of error points this result costs.
func (r Result) Weight() int { return r.Points }

// OK reports success.
func OK(format string, args ...any) Result { return result(health.StatusOK, format, args...) }

// Warning reports a degraded but working service.
func Warning(format string, args ...any) Result {
	return result(health.StatusWarning, format, args...)
}

// Critical reports a failed service.
func Critical(format string, args ...any) Result {
	return result(health.StatusCritical, format, args...)
}

// Unknown reports that the probe could not reach a verdict, for example because
// the container's address could not be resolved.
func Unknown(format string, args ...any) Result {
	return result(health.StatusUnknown, format, args...)
}

func result(status health.Status, format string, args ...any) Result {
	return Result{
		Status:  status,
		Message: fmt.Sprintf(format, args...),
		Points:  int(status),
	}
}

// Cost fixes what a failure of p costs, regardless of how severe the probe
// itself considers it.
//
// watchdog.sh was not uniform here. Probes that shelled out to a Nagios plugin
// folded in its exit code, so a CRITICAL moved twice as fast towards a restart
// as a WARNING. Probes the script implemented itself — the DNSSEC flag, the
// Redis state keys, the mail queue, the external relay test — always added
// exactly one point. Wrapping those in Cost(1, …) keeps the thresholds shipped
// in mailcow.conf calibrated the way they were, while leaving each probe free to
// report the severity it actually observed for logs and metrics.
func Cost(points int, p Probe) Probe { return &costProbe{points: points, inner: p} }

type costProbe struct {
	points int
	inner  Probe
}

func (p *costProbe) Name() string { return p.inner.Name() }

func (p *costProbe) Run(ctx context.Context) Result {
	res := p.inner.Run(ctx)
	if res.Status != health.StatusOK {
		res.Points = p.points
	}
	return res
}

// Run executes p under the probe timeout and stamps the result with the probe's
// name and wall-clock duration. A probe that panics is reported as UNKNOWN
// rather than taking the watchdog down with it.
func Run(ctx context.Context, p Probe) (res Result) {
	start := time.Now()

	defer func() {
		if r := recover(); r != nil {
			// A bug in one probe must not take the whole watchdog down; report
			// it as an unresolved check and keep the other loops running.
			res = Unknown("probe panicked: %v", r)
		}
		res.Probe = p.Name()
		res.Duration = time.Since(start)
	}()

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return p.Run(ctx)
}

// Addr resolves a target's address at probe time. Container addresses change
// across restarts, so checks re-resolve them on every round exactly as
// get_container_ip did.
type Addr func(ctx context.Context) (string, error)

// Static returns an Addr for a fixed host.
func Static(host string) Addr {
	return func(context.Context) (string, error) { return host, nil }
}

// dialer opens IPv4 connections. Every Nagios invocation in watchdog.sh passed
// -4: the mailcow bridge network is IPv4 and a stray AAAA record would make the
// probe fail for the wrong reason.
var dialer = &net.Dialer{}

// dial connects to host:port over IPv4, honouring the context deadline.
func dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(host, fmt.Sprint(port)))
}

// tlsConfig returns the client configuration used for every internal TLS probe.
//
// Verification is off by design: the probes connect to container IPs while the
// certificates are issued for the public MAILCOW_HOSTNAME, so a verified
// handshake could never succeed. The Nagios plugins behaved the same way — they
// only ever inspected the certificate's validity dates, which certExpiry does
// explicitly.
func tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		//nolint:gosec // G402: see the doc comment — internal probes connect by
		// IP to certificates issued for the public hostname.
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	}
}

// certExpiry turns a peer certificate chain into a verdict, mirroring the
// Nagios `-D <days>` option: fewer than minDays of validity left is CRITICAL,
// and a certificate that is not yet valid is CRITICAL too.
func certExpiry(state tls.ConnectionState, minDays int, label string) Result {
	if len(state.PeerCertificates) == 0 {
		return Critical("%s: server presented no certificate", label)
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()

	if now.Before(leaf.NotBefore) {
		return Critical("%s: certificate is not valid before %s",
			label, leaf.NotBefore.Format(time.RFC3339))
	}

	left := leaf.NotAfter.Sub(now)
	days := int(left.Hours() / 24)
	switch {
	case left <= 0:
		return Critical("%s: certificate expired on %s",
			label, leaf.NotAfter.Format(time.RFC3339))
	case days < minDays:
		return Critical("%s: certificate expires in %d days (%s), minimum is %d",
			label, days, leaf.NotAfter.Format(time.RFC3339), minDays)
	default:
		return OK("%s: certificate valid for %d more days (until %s)",
			label, days, leaf.NotAfter.Format(time.RFC3339))
	}
}

// resolve turns an Addr into a host, converting a failure into the UNKNOWN
// verdict every probe uses for "could not even start".
func resolve(ctx context.Context, addr Addr, name string) (string, *Result) {
	host, err := addr(ctx)
	if err != nil {
		r := Unknown("%s: cannot resolve target: %v", name, err)
		return "", &r
	}
	return host, nil
}
