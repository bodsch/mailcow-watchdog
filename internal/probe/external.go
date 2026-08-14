package probe

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ExternalEndpoint is the mailcow-operated relay test. It reports back whether
// the installation looks like an open relay from the outside.
const ExternalEndpoint = "https://checks.mailcow.email"

// externalConnectTimeout mirrors `curl --connect-timeout 3 -m 10`.
const externalConnectTimeout = 3 * time.Second

// External asks checks.mailcow.email whether this installation is an open relay.
//
// One probe covers one address family. watchdog.sh ran the test over IPv4 and
// IPv6 separately and added one error point per failing family — and, through a
// copy/paste slip, always stored the IPv4 response body even when it was the
// IPv6 test that failed. Here each probe keeps its own transcript.
type External struct {
	name    string
	network string
	url     string
	guid    GUIDFunc
	client  *http.Client

	mu      sync.Mutex
	details string
}

// GUIDFunc returns the installation identifier the endpoint expects. It is a
// function rather than a value because the identifier lives in the database,
// which may not be reachable when the probe is constructed.
type GUIDFunc func(ctx context.Context) (string, error)

// NewExternal returns an open relay probe. network is "tcp4" or "tcp6".
func NewExternal(name, network, endpoint string, guid GUIDFunc) *External {
	return &External{
		name:    name,
		network: network,
		url:     endpoint,
		guid:    guid,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					// Pinning the family is the point: the whole reason for two
					// probes is to learn which of the two is misconfigured.
					d := &net.Dialer{Timeout: externalConnectTimeout}
					return d.DialContext(ctx, network, addr)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// Name implements Probe.
func (p *External) Name() string { return p.name }

// Run implements Probe.
func (p *External) Run(ctx context.Context) Result {
	guid, err := p.guid(ctx)
	if err != nil {
		return Unknown("%s: cannot read the mailcow GUID: %v", p.name, err)
	}

	form := url.Values{"guid": {guid}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Unknown("%s: cannot build the request: %v", p.name, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		// The endpoint being unreachable says nothing about this installation.
		// The shell treated an empty response the same way: not an error.
		return OK("%s: %s is not reachable over %s: %v", p.name, p.url, p.network, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OK("%s: could not read the response over %s: %v", p.name, p.network, err)
	}

	var reply struct {
		Response string `json:"response"`
		Out      string `json:"out"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return OK("%s: %s returned an unparsable answer over %s", p.name, p.url, p.network)
	}

	if reply.Response == "critical" {
		p.setDetails(reply.Out)
		return Critical("%s: %s reports this installation as an open relay over %s",
			p.name, p.url, p.network)
	}
	return OK("%s: %s reports %q over %s", p.name, p.url, orNA(reply.Response), p.network)
}

// Details returns the report body from the most recent failing round.
func (p *External) Details() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.details
}

func (p *External) setDetails(out string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.details = out
}
