package probe

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
)

// rspamdSettingsScore is the required_score mailcow's rspamd settings assign to
// mail from watchdog@localhost. It is deliberately absurd so that seeing it
// proves the settings map was loaded, not merely that rspamd is listening.
const rspamdSettingsScore = 9999

// rspamdProbeMessage is the message submitted for scanning. Its From address is
// what selects the settings rule above.
const rspamdProbeMessage = "To: null@localhost\r\n" +
	"From: watchdog@localhost\r\n" +
	"\r\n" +
	"Empty\r\n"

// Rspamd scans a fixed message through rspamd's normal worker and checks that
// the configured settings were applied.
//
// The scan goes over rspamd's unix socket rather than TCP, which is how the
// shell reached it too — this is why the probe does not need a container
// address. The socket is shared into the watchdog container by compose.
type Rspamd struct {
	name   string
	socket string
	client *http.Client
}

// NewRspamd returns a settings probe talking to rspamd through socket.
func NewRspamd(name, socket string) *Rspamd {
	return &Rspamd{
		name:   name,
		socket: socket,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					d := &net.Dialer{}
					return d.DialContext(ctx, "unix", socket)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// Name implements Probe.
func (p *Rspamd) Name() string { return p.name }

// Run implements Probe.
func (p *Rspamd) Run(ctx context.Context) Result {
	// The host in the URL is ignored by the unix-socket dialer but has to be
	// syntactically valid.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://rspamd/scan", strings.NewReader(rspamdProbeMessage))
	if err != nil {
		return Unknown("%s: cannot build the scan request: %v", p.name, err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := p.client.Do(req)
	if err != nil {
		return Critical("%s: scan through %s failed: %v", p.name, p.socket, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Critical("%s: cannot read the scan result: %v", p.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return Critical("%s: rspamd answered the scan with %s", p.name, resp.Status)
	}

	var scan struct {
		Default struct {
			RequiredScore float64 `json:"required_score"`
		} `json:"default"`
	}
	if err := json.Unmarshal(body, &scan); err != nil {
		return Critical("%s: cannot parse the scan result: %v", p.name, err)
	}

	// The shell compared the score with its decimals cut off, so 9999.0 and
	// 9999.9 both counted as a match.
	if score := int(scan.Default.RequiredScore); score != rspamdSettingsScore {
		return Critical("%s: settings check failed, score returned: %d (want %d)",
			p.name, score, rspamdSettingsScore)
	}
	return OK("%s: settings check succeeded, score returned: %d",
		p.name, rspamdSettingsScore)
}
