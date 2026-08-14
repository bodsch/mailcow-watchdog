package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
)

// HTTP performs a GET and grades the status code, replacing check_http.
//
// Nagios treats 2xx and 3xx as OK, 4xx as WARNING and 5xx as CRITICAL, and it
// does not follow redirects unless asked to. Both nginx-mailcow and sogo-mailcow
// are probed this way.
type HTTP struct {
	name   string
	addr   Addr
	port   int
	path   string
	client *http.Client
}

// NewHTTP returns an HTTP probe for http://addr:port/path.
func NewHTTP(name string, addr Addr, port int, path string) *HTTP {
	return &HTTP{
		name: name,
		addr: addr,
		port: port,
		path: path,
		client: &http.Client{
			// check_http reports the redirect itself rather than chasing it.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					// The mailcow bridge network is IPv4; every check_http call
					// in watchdog.sh passed -4.
					return dialer.DialContext(ctx, "tcp4", addr)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// Name implements Probe.
func (p *HTTP) Name() string { return p.name }

// Run implements Probe.
func (p *HTTP) Run(ctx context.Context) Result {
	host, bad := resolve(ctx, p.addr, p.name)
	if bad != nil {
		return *bad
	}

	target := (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, fmt.Sprint(p.port)),
		Path:   p.path,
	}).String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Unknown("%s: cannot build request for %s: %v", p.name, target, err)
	}
	req.Header.Set("User-Agent", "mailcow-watchdog")

	resp, err := p.client.Do(req)
	if err != nil {
		return Critical("%s: GET %s failed: %v", p.name, target, err)
	}
	defer resp.Body.Close()
	// Drain so the socket can be reused or closed cleanly; the body is not part
	// of the verdict.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, readLimit))

	switch {
	case resp.StatusCode >= 500:
		return Critical("%s: GET %s returned %s", p.name, target, resp.Status)
	case resp.StatusCode >= 400:
		return Warning("%s: GET %s returned %s", p.name, target, resp.Status)
	default:
		return OK("%s: GET %s returned %s", p.name, target, resp.Status)
	}
}
