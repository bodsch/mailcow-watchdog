// Package dockerapi restarts mailcow's containers and resolves their addresses.
//
// It speaks to either of two endpoints:
//
//   - the mailcow dockerapi service, a small HTTPS service mailcow puts in front
//     of the daemon so the watchdog can restart containers without being able to
//     do anything else. It presents a self-signed certificate, which is why this
//     client, and only this client, skips verification.
//   - the Docker daemon's own socket, for deployments that would rather not run
//     the extra container. This grants the watchdog the full Docker API, so it
//     is the less contained of the two options.
//
// The URL scheme picks both the transport and, unless overridden, the dialect.
package dockerapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// composeServiceLabel and composeProjectLabel identify a container's role and
// the stack it belongs to.
const (
	composeServiceLabel = "com.docker.compose.service"
	composeProjectLabel = "com.docker.compose.project"
)

// defaultTimeout bounds a single API call.
const defaultTimeout = 10 * time.Second

// reachTimeout bounds one reachability probe. It has to stay below the
// supervisor's poll interval, and it covers a TLS handshake against the
// dockerapi's 4096-bit key rather than a bare connection.
const reachTimeout = 3 * time.Second

// unixAuthority is the host part of every request URL over a unix socket. The
// dialer ignores the address, but net/http still needs a syntactically valid one.
const unixAuthority = "http://docker"

// Client talks to one API endpoint, scoped to one compose project.
type Client struct {
	baseURL string
	dialect Dialect
	project string
	// ipv4Network is the mailcow bridge prefix. A container attached to several
	// networks has several addresses and only the one on this network is
	// reachable from here.
	ipv4Network string

	http  *http.Client
	reach func(ctx context.Context) bool
}

// Options configures the client.
type Options struct {
	// BaseURL is the endpoint. Either an HTTPS URL such as
	// https://dockerapi.mailcowdockerized_mailcow-network, or a socket path such
	// as unix:///var/run/docker.sock.
	BaseURL string
	// Project is COMPOSE_PROJECT_NAME. Docker Compose lowercases project names,
	// so the comparison is case-insensitive.
	Project string
	// IPv4Network is IPV4_NETWORK, e.g. "172.22.1".
	IPv4Network string
	// Dialect overrides what the URL scheme implies, for the unusual combination
	// of a mailcow dockerapi reachable over a unix socket.
	Dialect Dialect
}

// New returns a client for the configured endpoint.
func New(opts Options) (*Client, error) {
	parsed, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing the docker API URL %q: %w", opts.BaseURL, err)
	}

	c := &Client{
		project:     strings.ToLower(opts.Project),
		ipv4Network: opts.IPv4Network,
	}

	var transport *http.Transport
	var implied Dialect

	switch parsed.Scheme {
	case "unix":
		socket := parsed.Path
		if socket == "" {
			// url.Parse puts the path in Opaque for unix:/path (one slash).
			socket = parsed.Opaque
		}
		if socket == "" {
			return nil, fmt.Errorf("the docker API URL %q names no socket path", opts.BaseURL)
		}
		transport = unixTransport(socket)
		c.baseURL = unixAuthority
		c.reach = dialUnix(socket)
		implied = DialectEngine

	case "https", "http":
		if parsed.Host == "" {
			return nil, fmt.Errorf("the docker API URL %q has no host", opts.BaseURL)
		}
		transport = tcpTransport(parsed.Scheme == "https")
		c.baseURL = strings.TrimSuffix(strings.TrimSuffix(opts.BaseURL, "/"), parsed.Path)
		// A plain HTTP endpoint has no TLS config, and the probe then stops at
		// the connection — there is no handshake to complete.
		c.reach = dialTCP(parsed, transport.TLSClientConfig)
		implied = DialectMailcow

	case "":
		return nil, fmt.Errorf("the docker API URL %q has no scheme, want https:// or unix://", opts.BaseURL)

	default:
		return nil, fmt.Errorf("unsupported docker API scheme %q, want https:// or unix://", parsed.Scheme)
	}

	c.dialect = opts.Dialect
	if c.dialect == DialectAuto {
		c.dialect = implied
	}
	c.http = &http.Client{Timeout: defaultTimeout, Transport: transport}

	return c, nil
}

// Dialect reports which flavour of API the client ended up talking.
func (c *Client) Dialect() Dialect { return c.dialect }

// unixTransport dials the socket for every request, ignoring the URL authority.
func unixTransport(socket string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{}
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
}

func tcpTransport(secure bool) *http.Transport {
	transport := &http.Transport{DisableKeepAlives: true}
	if secure {
		transport.TLSClientConfig = &tls.Config{
			// G402: the mailcow dockerapi service presents a self-signed
			// certificate on an internal-only network. watchdog.sh passed
			// curl --insecure for exactly this reason; there is no CA to verify
			// against.
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         tls.VersionTLS12,
		}
	}
	return transport
}

func dialUnix(socket string) func(context.Context) bool {
	return func(ctx context.Context) bool {
		d := &net.Dialer{Timeout: reachTimeout}
		conn, err := d.DialContext(ctx, "unix", socket)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
}

// dialTCP probes a TCP endpoint. A non-nil tlsConfig makes the probe complete the
// TLS handshake instead of stopping at the connection.
//
// Two reasons to carry the handshake through. It answers the question actually
// being asked — a listener that accepts but cannot serve TLS is not an endpoint
// this client can use, and the supervisor would keep every check paused waiting
// for one that is never coming. And it leaves the server nothing to report:
// closing before the ClientHello is what makes mailcow-dockerapi log a failed
// handshake, once per poll, for as long as the watchdog runs.
func dialTCP(endpoint *url.URL, tlsConfig *tls.Config) func(context.Context) bool {
	addr := net.JoinHostPort(endpoint.Hostname(), reachPort(endpoint))

	return func(ctx context.Context) bool {
		dialer := &net.Dialer{Timeout: reachTimeout}

		var conn net.Conn
		var err error
		if tlsConfig == nil {
			conn, err = dialer.DialContext(ctx, "tcp", addr)
		} else {
			// The config is the transport's, so the probe applies the same TLS
			// policy as a request would — including the skipped verification of
			// the self-signed certificate. What is tested is that the server
			// completes a handshake, not who it claims to be.
			tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsConfig}
			conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return false
		}

		_ = conn.Close()
		return true
	}
}

// reachPort is the port to probe, defaulted from the scheme the way a request
// would default it.
func reachPort(endpoint *url.URL) string {
	if port := endpoint.Port(); port != "" {
		return port
	}
	if endpoint.Scheme == "http" {
		return "80"
	}
	return "443"
}

// List returns every running container in this compose project.
//
// Start times are only populated for the mailcow dialect, whose list returns
// full inspect records. Use Find when the uptime matters.
func (c *Client) List(ctx context.Context) ([]Container, error) {
	var all []Container

	switch c.dialect {
	case DialectEngine:
		var raw []summaryRecord
		if err := c.get(ctx, "/containers/json", &raw); err != nil {
			return nil, err
		}
		for _, record := range raw {
			all = append(all, record.normalise())
		}

	default:
		var raw []inspectRecord
		if err := c.get(ctx, "/containers/json", &raw); err != nil {
			return nil, err
		}
		for _, record := range raw {
			all = append(all, record.normalise())
		}
	}

	mine := make([]Container, 0, len(all))
	for _, container := range all {
		// Several mailcow stacks can share a daemon, so the project label is
		// what keeps the watchdog from restarting the neighbour's containers.
		if c.project != "" && !strings.Contains(strings.ToLower(container.Project), c.project) {
			continue
		}
		mine = append(mine, container)
	}
	return mine, nil
}

// Find returns the containers whose compose service name is exactly service,
// with their start times filled in.
//
// The match is exact on purpose: watchdog.sh compared exactly here and used a
// substring comparison when restarting, and that mismatch is why its certificate
// check asked for "postfix" and got nothing back.
func (c *Client) Find(ctx context.Context, service string) ([]Container, error) {
	all, err := c.List(ctx)
	if err != nil {
		return nil, err
	}

	var matched []Container
	for _, container := range all {
		if container.Service != service {
			continue
		}
		// The daemon's container list carries no start time, so the uptime rule
		// the supervisor applies needs one inspection per match. Restarts are
		// rare enough for that to be cheaper than inspecting on every round.
		if container.StartedAt == "" && c.dialect == DialectEngine {
			full, err := c.Inspect(ctx, container.ID)
			if err != nil {
				return nil, err
			}
			container.StartedAt = full.StartedAt
		}
		matched = append(matched, container)
	}
	return matched, nil
}

// IP returns an address for service on the mailcow network.
//
// A scaled service has several containers; one is picked at random so that
// repeated probes spread across the replicas, which is what the shell's `shuf`
// achieved. This deliberately uses the cheap list rather than Find, because it
// runs on every round of every check.
func (c *Client) IP(ctx context.Context, service string) (string, error) {
	all, err := c.List(ctx)
	if err != nil {
		return "", err
	}

	var matched []Container
	for _, container := range all {
		if container.Service == service {
			matched = append(matched, container)
		}
	}
	if len(matched) == 0 {
		return "", fmt.Errorf("no container runs the service %q in project %q", service, c.project)
	}

	rand.Shuffle(len(matched), func(i, j int) { matched[i], matched[j] = matched[j], matched[i] })

	for _, container := range matched {
		if ip := c.pickAddress(container); ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("service %q has no address on network %q", service, c.ipv4Network)
}

// pickAddress returns the container's address on the mailcow bridge. Containers
// attached to several networks also answer on addresses this host cannot reach.
func (c *Client) pickAddress(container Container) string {
	for _, address := range container.Networks {
		if c.ipv4Network != "" && !strings.HasPrefix(address, c.ipv4Network) {
			continue
		}
		return address
	}
	return ""
}

// Inspect returns one container's current state.
func (c *Client) Inspect(ctx context.Context, id string) (Container, error) {
	var record inspectRecord
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &record); err != nil {
		return Container{}, err
	}
	return record.normalise(), nil
}

// Restart asks the daemon to restart a container.
func (c *Client) Restart(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/restart", nil)
}

// Top returns the container's process list, one string slice per process.
func (c *Client) Top(ctx context.Context, id string) ([][]string, error) {
	path := "/containers/" + url.PathEscape(id) + "/top"

	if c.dialect == DialectEngine {
		// The daemon serves top as a GET and answers with the process table
		// directly.
		var reply struct {
			Processes [][]string `json:"Processes"`
		}
		if err := c.get(ctx, path, &reply); err != nil {
			return nil, err
		}
		return reply.Processes, nil
	}

	// The mailcow service serves it as a POST and wraps the table in "msg".
	var reply struct {
		Msg struct {
			Processes [][]string `json:"Processes"`
		} `json:"msg"`
	}
	if err := c.do(ctx, http.MethodPost, path, &reply); err != nil {
		return nil, err
	}
	return reply.Msg.Processes, nil
}

// Running reports whether any of the container's processes has a command line
// containing want.
//
// The watchdog uses this to spot php-fpm initialising the database: restarting
// that container mid-migration would leave the schema half-written.
func (c *Client) Running(ctx context.Context, id, want string) (bool, error) {
	processes, err := c.Top(ctx, id)
	if err != nil {
		return false, err
	}
	for _, process := range processes {
		if strings.Contains(strings.Join(process, " "), want) {
			return true, nil
		}
	}
	return false, nil
}

// Reachable reports whether the endpoint can be connected to — over HTTPS,
// whether it completes a TLS handshake, which is the weakest thing a request
// needs from it.
//
// The supervisor pauses every check while this is false: without the API it
// cannot resolve container addresses, so the probes would fail for a reason that
// has nothing to do with the services they watch.
func (c *Client) Reachable(ctx context.Context) bool { return c.reach(ctx) }

func (c *Client) get(ctx context.Context, path string, into any) error {
	return c.do(ctx, http.MethodGet, path, into)
}

func (c *Client) do(ctx context.Context, method, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("building the %s %s request: %w", method, path, err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("reading the %s %s response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s returned %s", method, path, resp.Status)
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("decoding the %s %s response: %w", method, path, err)
	}
	return nil
}
