package check

import (
	"context"

	"bodsch.me/mailcow-watchdog/internal/dockerapi"
	"bodsch.me/mailcow-watchdog/internal/probe"
)

// Resolver turns a compose service name into an address a probe can dial.
type Resolver interface {
	Addr(service string) probe.Addr
}

// DNSResolver hands the service name straight to the dialer.
//
// mailcow gives every container a network alias matching its compose service
// name, so the platform resolver already knows how to reach it. watchdog.sh ran
// `dig a <service> +short` and dialled the result; letting the dialer resolve
// removes a step and, when the name does not exist, produces an error naming the
// service instead of the shell's placeholder address 240.0.0.0.
type DNSResolver struct{}

// Addr implements Resolver.
func (DNSResolver) Addr(service string) probe.Addr { return probe.Static(service) }

// APIResolver asks the dockerapi for a container's address on the mailcow
// network, which is what IP_BY_DOCKER_API=1 selects.
//
// The lookup happens per round rather than once, because a restarted container
// comes back with a new address.
type APIResolver struct {
	client *dockerapi.Client
}

// NewAPIResolver returns a Resolver backed by the dockerapi.
func NewAPIResolver(client *dockerapi.Client) *APIResolver {
	return &APIResolver{client: client}
}

// Addr implements Resolver.
func (r *APIResolver) Addr(service string) probe.Addr {
	return func(ctx context.Context) (string, error) {
		return r.client.IP(ctx, service)
	}
}
