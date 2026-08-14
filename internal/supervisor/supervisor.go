package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"bodsch.me/mailcow-watchdog/internal/check"
	"bodsch.me/mailcow-watchdog/internal/dockerapi"
	"bodsch.me/mailcow-watchdog/internal/metrics"
	"bodsch.me/mailcow-watchdog/internal/notify"
	"bodsch.me/mailcow-watchdog/internal/store"
)

// The timings the shell used around a container restart, kept as named
// constants so the reasoning behind each one is visible.
const (
	// MinUptime is how long a container must have been running before the
	// watchdog will restart it. Without it, a container that crashes on startup
	// would be restarted forever at the rate its checks run.
	MinUptime = 360 * time.Second

	// PauseBeforeRestart lets in-flight probes finish before the container goes
	// away, so their failures are not attributed to the restart.
	PauseBeforeRestart = 10 * time.Second

	// SettleAfterRestart gives the container time to come up before the checks
	// resume; without it every check would immediately spend more of its budget
	// on a service that is merely still starting.
	SettleAfterRestart = 35 * time.Second

	// InitDBDelay is how long the watchdog waits when php-fpm is migrating the
	// database instead of restarting it.
	InitDBDelay = 60 * time.Second

	// HealPoints is what every check gets back after the supervisor has acted.
	HealPoints = 2

	// DockerAPIPoll is how often the watcher retests an unreachable dockerapi.
	DockerAPIPoll = 3 * time.Second
)

// Notification throttles from the shell's notify_error calls.
const (
	replicationThrottle = 10 * time.Minute
	certThrottle        = 24 * time.Hour
)

// Docker is the part of the dockerapi client the supervisor needs.
type Docker interface {
	Find(ctx context.Context, service string) ([]dockerapi.Container, error)
	Restart(ctx context.Context, id string) error
	Running(ctx context.Context, id, want string) (bool, error)
	Reachable(ctx context.Context) bool
}

// Whois resolves the owner of a banned address.
type Whois interface {
	Lookup(ctx context.Context, query string) (string, error)
}

// Options configures the supervisor.
type Options struct {
	Checks     []*check.Check
	Docker     Docker
	Store      store.Store
	Dispatcher *notify.Dispatcher
	Metrics    *metrics.Metrics
	Whois      Whois
	Clock      Clock
	Log        *slog.Logger
	// NotifyBans mirrors WATCHDOG_NOTIFY_BAN: bans are always logged, but only
	// mailed when this is set.
	NotifyBans bool
}

// Supervisor owns the check runners and acts on the events they raise.
//
// It replaces watchdog.sh's main loop, its worker monitor and its dockerapi
// watcher. The FIFO those three communicated through is now a channel, which
// means an event carries the check that raised it rather than a bare string the
// loop had to re-interpret.
type Supervisor struct {
	runners    []*Runner
	byName     map[string]*Runner
	gate       *Gate
	docker     Docker
	store      store.Store
	dispatcher *notify.Dispatcher
	metrics    *metrics.Metrics
	whois      Whois
	clock      Clock
	log        *slog.Logger
	notifyBans bool

	events chan Event
}

// New builds a supervisor for the given checks.
func New(opts Options) (*Supervisor, error) {
	if len(opts.Checks) == 0 {
		return nil, errors.New("no checks are enabled")
	}
	if opts.Metrics == nil {
		return nil, errors.New("no metrics supplied")
	}
	if opts.Store == nil {
		return nil, errors.New("no store supplied")
	}
	if opts.Clock == nil {
		opts.Clock = Realtime{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	s := &Supervisor{
		gate:       NewGate(),
		docker:     opts.Docker,
		store:      opts.Store,
		dispatcher: opts.Dispatcher,
		metrics:    opts.Metrics,
		whois:      opts.Whois,
		clock:      opts.Clock,
		log:        opts.Log.With("component", "supervisor"),
		notifyBans: opts.NotifyBans,
		// The buffer keeps a check from blocking on a busy supervisor; one slot
		// per check is enough, since a check raises at most one event per round.
		events: make(chan Event, len(opts.Checks)),
		byName: make(map[string]*Runner, len(opts.Checks)),
	}

	deps := RunnerDeps{
		Gate:    s.gate,
		Clock:   opts.Clock,
		Store:   opts.Store,
		Metrics: opts.Metrics,
		Events:  s.events,
		Log:     opts.Log,
	}
	for _, c := range opts.Checks {
		runner := NewRunner(c, deps)
		s.runners = append(s.runners, runner)
		s.byName[c.Name] = runner
		opts.Metrics.InitCheck(c.Name, c.Threshold)
	}

	return s, nil
}

// Run starts every check and handles their events until ctx is cancelled.
func (s *Supervisor) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	for _, runner := range s.runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runner.Run(ctx)
		}()
	}

	if s.docker != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.watchDockerAPI(ctx)
		}()
	}

	s.log.Info("watchdog is monitoring mailcow", "checks", len(s.runners))
	s.handleEvents(ctx)

	wg.Wait()
	s.log.Info("watchdog stopped")
	return nil
}

// handleEvents is the former main loop.
func (s *Supervisor) handleEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.events:
			s.handle(ctx, event)
		}
	}
}

// handle acts on one event. The branches follow the shell's if/elif chain, in
// the same order, because the order is load-bearing: acme-mailcow is caught
// before the container branch and so never triggers a restart.
func (s *Supervisor) handle(ctx context.Context, event Event) {
	c := event.Check

	switch c.Event {
	case "ratelimit":
		s.log.Warn("at least one ratelimit was applied")
		s.alert(ctx, notify.Alert{Service: c.Event, Details: c.Details(ctx)})

	case "mail_queue_status":
		s.log.Warn("mail queue status is critical")
		s.alert(ctx, notify.Alert{Service: c.Event, Details: c.Details(ctx)})

	case "external_checks":
		s.log.Error("your mailcow is an open relay")
		s.alert(ctx, notify.Alert{
			Service: c.Event,
			Message: "Please stop mailcow now and check your network configuration!",
			Details: c.Details(ctx),
		})

	case "mysql_repl_checks":
		s.log.Warn("MySQL replication is not working properly")
		s.alert(ctx, notify.Alert{
			Service:  c.Event,
			Message:  "Please check the SQL replication status",
			Details:  c.Details(ctx),
			Throttle: replicationThrottle,
		})

	case "dovecot_repl_checks":
		s.log.Warn("Dovecot replication is not working properly")
		s.alert(ctx, notify.Alert{
			Service:  c.Event,
			Message:  "Please check the Dovecot replicator status",
			Details:  c.Details(ctx),
			Throttle: replicationThrottle,
		})

	case "certcheck":
		s.log.Warn("certificates are about to expire")
		s.alert(ctx, notify.Alert{
			Service:  c.Event,
			Message:  "Please renew your certificate",
			Details:  c.Details(ctx),
			Throttle: certThrottle,
		})

	case "acme-mailcow":
		s.log.Warn("acme-mailcow did not complete successfully")
		s.alert(ctx, notify.Alert{
			Service: c.Event,
			Message: "Please check acme-mailcow for further information.",
			Details: c.Details(ctx),
		})

	case "fail2ban":
		s.handleBans(ctx, c)

	default:
		if c.RestartsContainer() {
			s.restart(ctx, c)
			return
		}
		// A check whose event matches none of the branches would be silently
		// ignored by the shell. Say so instead.
		s.log.Error("no action is defined for this event", "event", c.Event)
		s.metrics.ObserveEvent(c.Event, "unhandled")
	}
}

// handleBans notifies once per newly banned address, with the registry record as
// the body.
func (s *Supervisor) handleBans(ctx context.Context, c *check.Check) {
	s.metrics.ObserveEvent(c.Event, "notify")

	var bans []string
	if c.Bans != nil {
		bans = c.Bans()
	}

	for _, host := range bans {
		s.log.Warn("banned", "host", host)

		details := ""
		if s.whois != nil {
			record, err := s.whois.Lookup(ctx, host)
			if err != nil {
				s.log.Debug("whois lookup failed", "host", host, "err", err)
			} else {
				details = record
			}
		}

		if !s.notifyBans {
			continue
		}
		s.alert(ctx, notify.Alert{
			Service: c.Event,
			Message: "IP ban: " + host,
			Details: details,
		})
	}
}

// restart pauses every check, restarts the container and lets the stack settle
// before resuming.
//
// The pause is what the shell achieved with `kill -STOP` on all of its workers:
// while a container is down, every check that touches it would spend budget on a
// failure the watchdog itself caused.
func (s *Supervisor) restart(ctx context.Context, c *check.Check) {
	container := c.Event

	s.pauseAll()
	defer s.resumeAll()

	if err := s.clock.Sleep(ctx, PauseBeforeRestart); err != nil {
		return
	}

	if s.docker == nil {
		s.log.Error("cannot restart a container without a dockerapi client", "container", container)
		s.metrics.ObserveRestart(container, "failed")
		return
	}

	matched, err := s.docker.Find(ctx, container)
	if err != nil {
		s.log.Error("cannot look up the container", "container", container, "err", err)
		s.metrics.ObserveRestart(container, "failed")
		return
	}
	if len(matched) == 0 {
		s.log.Error("no such container", "container", container)
		s.metrics.ObserveRestart(container, "failed")
		return
	}

	for _, target := range matched {
		s.restartOne(ctx, container, target, c)
	}
}

func (s *Supervisor) restartOne(ctx context.Context, container string, target dockerapi.Container, c *check.Check) {
	started, err := target.Started()
	if err != nil {
		s.log.Warn("cannot read the container's start time", "container", container, "err", err)
	}

	// A container that has only just come up is probably still starting, or is
	// crash-looping; restarting it again would only speed the loop up.
	if !started.IsZero() {
		if uptime := s.clock.Now().Sub(started); uptime < MinUptime {
			s.log.Info("container is running for less than the minimum uptime, skipping action",
				"container", container, "uptime", uptime.Truncate(time.Second), "minimum", MinUptime)
			s.metrics.ObserveRestart(container, "skipped")
			return
		}
	}

	if container == check.PHPFPMService {
		busy, err := s.docker.Running(ctx, target.ID, check.InitDBProcess)
		if err != nil {
			s.log.Warn("cannot read the container's process list", "container", container, "err", err)
		}
		if busy {
			// Interrupting a schema migration is worse than a slow web UI.
			s.log.Info("database is being initialized by php-fpm-mailcow, " +
				"not restarting but delaying checks for a minute")
			s.metrics.ObserveRestart(container, "skipped")
			_ = s.clock.Sleep(ctx, InitDBDelay)
			return
		}
	}

	s.log.Warn("restarting container", "container", container, "id", shortID(target.ID))
	if err := s.docker.Restart(ctx, target.ID); err != nil {
		s.log.Error("restart failed", "container", container, "err", err)
		s.metrics.ObserveRestart(container, "failed")
		return
	}

	s.metrics.ObserveRestart(container, "restarted")
	s.metrics.ObserveEvent(c.Event, "restart")
	s.logToRedis(ctx, fmt.Sprintf("Sent restart command to %s", container))
	s.alert(ctx, notify.Alert{Service: c.Event, Details: c.Details(ctx)})

	s.log.Info("waiting for the restarted container to settle")
	_ = s.clock.Sleep(ctx, SettleAfterRestart)
}

// watchDockerAPI pauses the checks while the dockerapi is unreachable.
//
// Without the API the watchdog cannot resolve container addresses or restart
// anything, so every check would fail for a reason that says nothing about the
// service it watches — and would eventually exhaust its budget on it.
func (s *Supervisor) watchDockerAPI(ctx context.Context) {
	held := false

	for {
		if err := s.clock.Sleep(ctx, DockerAPIPoll); err != nil {
			if held {
				s.resumeAll()
			}
			return
		}

		reachable := s.docker.Reachable(ctx)
		switch {
		case !reachable && !held:
			s.log.Warn("cannot find dockerapi-mailcow, waiting to recover")
			s.pauseAll()
			held = true

		case reachable && held:
			s.log.Info("dockerapi-mailcow is back, resuming checks")
			s.resumeAll()
			// The checks lost ground while the API was down through no fault of
			// the services they watch, so hand the points back.
			s.healAll()
			held = false
		}
	}
}

func (s *Supervisor) pauseAll() {
	s.gate.Pause()
	s.metrics.SetPaused(true)
}

func (s *Supervisor) resumeAll() {
	s.gate.Resume()
	s.metrics.SetPaused(false)
}

// healAll repays error points to every check.
//
// watchdog.sh meant to do this with `kill -USR1`, but wrote its trap body in
// double quotes, so ${err_count} expanded to 0 when the trap was installed and
// the reduction never happened. This is that feature working.
func (s *Supervisor) healAll() {
	for _, runner := range s.runners {
		runner.Heal(HealPoints)
	}
}

// alert renders and delivers a notification, recording the outcome.
func (s *Supervisor) alert(ctx context.Context, a notify.Alert) {
	if s.dispatcher == nil {
		s.metrics.ObserveNotification("disabled")
		return
	}
	if err := s.dispatcher.Dispatch(ctx, a); err != nil {
		s.log.Error("cannot deliver notification", "service", a.Service, "err", err)
		s.metrics.ObserveNotification("failed")
		return
	}
	s.metrics.ObserveNotification("sent")
}

// logToRedis mirrors the shell's log_msg, whose entries the mailcow UI shows
// alongside the health records.
func (s *Supervisor) logToRedis(ctx context.Context, message string) {
	if err := s.store.LogMessage(ctx, message); err != nil && ctx.Err() == nil {
		s.log.Warn("cannot write the log record", "err", err)
	}
}

// Snapshot returns each check's current health, for the readiness endpoint and
// for tests.
func (s *Supervisor) Snapshot() map[string]int {
	out := make(map[string]int, len(s.runners))
	for _, runner := range s.runners {
		out[runner.Name()] = runner.Snapshot().Percent
	}
	return out
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
