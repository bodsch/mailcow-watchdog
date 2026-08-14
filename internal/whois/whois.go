// Package whois looks up who owns a banned address.
//
// It replaces the `timeout 2s whois "${host}"` the shell ran before sending a
// ban notification. The registry data is the only reason the notification is
// worth reading: an operator wants to know whether the address belongs to a
// datacentre, a residential ISP or their own office.
package whois

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Port is the whois well-known port.
const Port = "43"

// RootServer is IANA's whois, which answers for every address and refers the
// caller to the responsible regional registry.
const RootServer = "whois.iana.org"

// DefaultTimeout bounds the whole lookup, both queries included. The shell
// allowed two seconds; a ban notification is not worth blocking the event loop
// for longer.
const DefaultTimeout = 2 * time.Second

// DialFunc opens a connection to a whois server.
type DialFunc func(ctx context.Context, addr string) (net.Conn, error)

// Client performs whois lookups.
type Client struct {
	root    string
	timeout time.Duration
	dial    DialFunc
}

// Options configures the client.
type Options struct {
	// Root is the server asked first. It defaults to RootServer.
	Root string
	// Timeout defaults to DefaultTimeout.
	Timeout time.Duration
	// Dial defaults to a plain TCP dialer.
	Dial DialFunc
}

// New returns a whois client.
func New(opts Options) *Client {
	if opts.Root == "" {
		opts.Root = RootServer
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Dial == nil {
		opts.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
			d := &net.Dialer{}
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	return &Client{root: opts.Root, timeout: opts.Timeout, dial: opts.Dial}
}

// Lookup returns the registry record for query.
//
// IANA answers for every address but only with a pointer to the regional
// registry, so the referral is followed once. If the second query fails, the
// referral answer is still returned — a partial record beats none.
func (c *Client) Lookup(ctx context.Context, query string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	root, err := c.ask(ctx, c.root, query)
	if err != nil {
		return "", fmt.Errorf("querying %s: %w", c.root, err)
	}

	referral := referral(root)
	if referral == "" || referral == c.root {
		return root, nil
	}

	detailed, err := c.ask(ctx, referral, query)
	if err != nil {
		return root, nil
	}
	return detailed, nil
}

// ask runs one whois query. The protocol is a single line in, everything until
// EOF out.
func (c *Client) ask(ctx context.Context, server, query string) (string, error) {
	conn, err := c.dial(ctx, net.JoinHostPort(server, Port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", fmt.Errorf("sending the query: %w", err)
	}

	// The cap keeps a chatty or hostile server from turning a ban notification
	// into a megabyte of mail.
	body, err := io.ReadAll(io.LimitReader(conn, 64<<10))
	if err != nil && len(body) == 0 {
		return "", fmt.Errorf("reading the answer: %w", err)
	}
	return string(body), nil
}

// referral extracts the regional registry IANA points at.
func referral(answer string) string {
	scanner := bufio.NewScanner(strings.NewReader(answer))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(strings.ToLower(line), "refer:") {
			continue
		}
		if server := strings.TrimSpace(line[len("refer:"):]); server != "" {
			return server
		}
	}
	return ""
}
