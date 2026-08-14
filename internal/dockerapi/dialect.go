package dockerapi

import (
	"fmt"
	"strings"
	"time"
)

// Dialect is the flavour of API on the other end of the connection.
//
// The two speak the same endpoints but shape their answers differently, so the
// client normalises both into Container rather than leaking the difference into
// the supervisor.
type Dialect int

const (
	// DialectAuto derives the dialect from the URL scheme: a unix socket is
	// assumed to be the Docker daemon, anything else the mailcow service.
	DialectAuto Dialect = iota
	// DialectMailcow is the mailcow dockerapi container, a small HTTPS service
	// in front of the daemon. Its container list returns full inspect records,
	// and its top endpoint wraps the answer in a "msg" object.
	DialectMailcow
	// DialectEngine is the Docker daemon's own API. Its container list returns
	// summary records with the labels at the top level and no start time, and
	// its top endpoint is a GET returning {Titles, Processes}.
	DialectEngine
)

// String implements fmt.Stringer.
func (d Dialect) String() string {
	switch d {
	case DialectAuto:
		return "auto"
	case DialectMailcow:
		return "mailcow"
	case DialectEngine:
		return "engine"
	default:
		return "invalid"
	}
}

// ParseDialect maps the DOCKER_API_DIALECT setting onto a Dialect.
func ParseDialect(value string) (Dialect, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return DialectAuto, nil
	case "mailcow":
		return DialectMailcow, nil
	case "engine", "docker":
		return DialectEngine, nil
	default:
		return DialectAuto, fmt.Errorf("unknown dialect %q, want auto, mailcow or engine", value)
	}
}

// Container is the normalised view of a container, identical for both dialects.
type Container struct {
	// ID is the full container id.
	ID string
	// Service is the compose service name, which is what the watchdog knows a
	// container by.
	Service string
	// Project is the compose project the container belongs to.
	Project string
	// Networks maps network name to the container's address on it.
	Networks map[string]string
	// StartedAt is the raw RFC3339 start time, empty when the source did not
	// report one. The Docker daemon's container list omits it, so a Container
	// built from a list may have to be inspected before its uptime is known.
	StartedAt string
}

// Started parses the start time. A container that never started carries
// Docker's zero timestamp, which is reported as the zero time.
func (c Container) Started() (time.Time, error) {
	if c.StartedAt == "" {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339Nano, c.StartedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing StartedAt %q: %w", c.StartedAt, err)
	}
	if at.Year() <= 1 {
		return time.Time{}, nil
	}
	return at, nil
}

// networks is the address block both dialects share.
type networks struct {
	Networks map[string]struct {
		IPAddress string `json:"IPAddress"`
	} `json:"Networks"`
}

// addresses flattens the block into a name/address map.
func (n networks) addresses() map[string]string {
	out := make(map[string]string, len(n.Networks))
	for name, network := range n.Networks {
		if network.IPAddress != "" {
			out[name] = network.IPAddress
		}
	}
	return out
}

// inspectRecord is what a container inspection returns, in either dialect, and
// also what every entry of the mailcow dockerapi's container list looks like.
type inspectRecord struct {
	ID string `json:"Id"`

	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`

	NetworkSettings networks `json:"NetworkSettings"`

	State struct {
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
}

func (r inspectRecord) normalise() Container {
	return Container{
		ID:        r.ID,
		Service:   r.Config.Labels[composeServiceLabel],
		Project:   r.Config.Labels[composeProjectLabel],
		Networks:  r.NetworkSettings.addresses(),
		StartedAt: r.State.StartedAt,
	}
}

// summaryRecord is one entry of the Docker daemon's container list.
//
// It differs from an inspection in two ways that matter: the labels sit at the
// top level rather than under Config, and State is a word such as "running"
// rather than an object — which is why it cannot share a type with
// inspectRecord and why the start time has to come from a separate inspection.
type summaryRecord struct {
	ID              string            `json:"Id"`
	Labels          map[string]string `json:"Labels"`
	NetworkSettings networks          `json:"NetworkSettings"`
}

func (r summaryRecord) normalise() Container {
	return Container{
		ID:       r.ID,
		Service:  r.Labels[composeServiceLabel],
		Project:  r.Labels[composeProjectLabel],
		Networks: r.NetworkSettings.addresses(),
	}
}
