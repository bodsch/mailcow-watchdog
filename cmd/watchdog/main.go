// Command watchdog monitors a mailcow installation and restarts the containers
// that stop answering.
//
// It is a drop-in replacement for the watchdog.sh that ships with mailcow: the
// same environment variables configure it, the same Redis keys carry its state
// and the same dockerapi service performs the restarts.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bodsch.me/mailcow-watchdog/internal/check"
	"bodsch.me/mailcow-watchdog/internal/config"
	"bodsch.me/mailcow-watchdog/internal/dockerapi"
	"bodsch.me/mailcow-watchdog/internal/metrics"
	"bodsch.me/mailcow-watchdog/internal/notify"
	"bodsch.me/mailcow-watchdog/internal/probe"
	"bodsch.me/mailcow-watchdog/internal/store"
	"bodsch.me/mailcow-watchdog/internal/supervisor"
	"bodsch.me/mailcow-watchdog/internal/whois"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	_ "github.com/go-sql-driver/mysql"
)

// version is set at build time from the Makefile.
var version = "dev"

// dependencyPoll is how often startup retests MariaDB and Redis. watchdog.sh
// used two seconds.
const dependencyPoll = 2 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("watchdog failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.EnvLookup)
	if err != nil {
		// The logger is not configured yet, so this goes out through the
		// default one rather than being swallowed.
		return err
	}

	log := newLogger(cfg.Log)
	slog.SetDefault(log)
	log.Info("mailcow watchdog starting",
		"version", version,
		"hostname", cfg.Mailcow.Hostname,
		"project", cfg.Mailcow.ComposeProject,
		"log_level", cfg.Log.Level,
		"verbose", cfg.Verbose)

	// Signals arrive here rather than in a goroutine so every stage of startup
	// can be interrupted cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	m := metrics.New(registry, version)

	readiness := &metrics.Readiness{}
	metricsServer := metrics.NewServer(cfg.Metrics.Listen, registry, readiness, log)

	metricsDone := make(chan error, 1)
	go func() { metricsDone <- metricsServer.Run(ctx) }()

	if !cfg.Enabled {
		// USE_WATCHDOG=n. Idling rather than exiting keeps docker-compose from
		// treating the container as a crash loop, which is why watchdog.sh slept
		// for a year and then re-executed itself.
		log.Warn("USE_WATCHDOG is disabled, monitoring nothing")
		readiness.SetReady(true)
		<-ctx.Done()
		return waitForMetrics(metricsDone)
	}

	if err := settle(ctx, cfg.SettleDelay, log); err != nil {
		return waitForMetrics(metricsDone)
	}

	deps, cleanup, err := connect(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer cleanup()

	sup, err := build(cfg, deps, m, log)
	if err != nil {
		return err
	}

	checkIPv6(ctx, cfg, deps.dispatcher, log)

	if cfg.Notify.OnStart {
		announceStart(ctx, deps.dispatcher, m, log)
	}

	readiness.SetReady(true)
	if err := sup.Run(ctx); err != nil {
		return err
	}
	return waitForMetrics(metricsDone)
}

// dependencies are the connections the checks share.
type dependencies struct {
	store      store.Store
	localStore probe.RedisPinger
	appDB      *sql.DB
	rootDB     *sql.DB
	docker     *dockerapi.Client
	dispatcher *notify.Dispatcher
}

// connect opens every external connection and waits for the ones the checks
// cannot start without.
func connect(ctx context.Context, cfg *config.Config, log *slog.Logger) (*dependencies, func(), error) {
	var closers []func()
	cleanup := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	appDB, err := sql.Open("mysql", cfg.DB.AppDSN())
	if err != nil {
		return nil, cleanup, fmt.Errorf("opening the mailcow database: %w", err)
	}
	// The pool is small on purpose: two probes at a time is all the checks need,
	// and idle connections against a restarting MariaDB are just noise.
	appDB.SetMaxOpenConns(4)
	appDB.SetMaxIdleConns(2)
	appDB.SetConnMaxLifetime(5 * time.Minute)
	closers = append(closers, func() { _ = appDB.Close() })

	var rootDB *sql.DB
	if cfg.Checks.MySQLRepl.Enabled {
		rootDB, err = sql.Open("mysql", cfg.DB.RootDSN())
		if err != nil {
			return nil, cleanup, fmt.Errorf("opening the database as root: %w", err)
		}
		rootDB.SetMaxOpenConns(2)
		rootDB.SetMaxIdleConns(1)
		rootDB.SetConnMaxLifetime(5 * time.Minute)
		closers = append(closers, func() { _ = rootDB.Close() })
	}

	redis := store.New(store.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password})
	closers = append(closers, func() { _ = redis.Close() })

	// Under REDIS_SLAVEOF the writes above go to the replication primary, but
	// the redis check's event restarts the local container — so that check needs
	// a handle on the local instance or it would measure the wrong machine.
	localRedis := redis
	if cfg.Redis.Addr != cfg.Redis.LocalAddr {
		localRedis = store.New(store.Options{
			Addr:     cfg.Redis.LocalAddr,
			Password: cfg.Redis.Password,
		})
		closers = append(closers, func() { _ = localRedis.Close() })
		log.Info("redis runs in replication",
			"primary", cfg.Redis.Addr, "local", cfg.Redis.LocalAddr)
	}

	// The checks would all fail identically until these are up, so the startup
	// waits rather than reporting a stack-wide outage that is really just a cold
	// start.
	if err := waitFor(ctx, log, "SQL", func(ctx context.Context) error {
		return appDB.PingContext(ctx)
	}); err != nil {
		return nil, cleanup, err
	}
	if err := waitFor(ctx, log, "Redis", redis.Ping); err != nil {
		return nil, cleanup, err
	}

	dialect, err := dockerapi.ParseDialect(cfg.Docker.Dialect)
	if err != nil {
		return nil, cleanup, fmt.Errorf("DOCKER_API_DIALECT: %w", err)
	}
	docker, err := dockerapi.New(dockerapi.Options{
		BaseURL:     cfg.Docker.BaseURL,
		Project:     cfg.Mailcow.ComposeProject,
		IPv4Network: cfg.Mailcow.IPv4Network,
		Dialect:     dialect,
	})
	if err != nil {
		return nil, cleanup, err
	}
	log.Info("docker API configured", "endpoint", cfg.Docker.BaseURL, "dialect", docker.Dialect())

	// Assigning the constructors' results straight into the variadic call would
	// wrap a nil pointer in a non-nil interface, which Multi would then call.
	var senders []notify.Notifier
	if mail := notify.NewSMTP(notify.SMTPOptions{
		From:       cfg.Notify.From,
		HELO:       cfg.Notify.HELO,
		Recipients: cfg.Notify.Emails,
	}, log); mail != nil {
		senders = append(senders, mail)
	}
	if hook := notify.NewWebhook(cfg.Notify.Webhook, cfg.Notify.WebhookBody, log); hook != nil {
		senders = append(senders, hook)
	}
	channels := notify.NewMulti(log, senders...)

	var dispatcher *notify.Dispatcher
	if channels.Enabled() {
		dispatcher = notify.NewDispatcher(channels, redis, cfg.Notify.Subject, log)
	} else {
		log.Info("no notification channel is configured, alerts will only be logged")
	}

	return &dependencies{
		store:      redis,
		localStore: localRedis,
		appDB:      appDB,
		rootDB:     rootDB,
		docker:     docker,
		dispatcher: dispatcher,
	}, cleanup, nil
}

// build assembles the checks and the supervisor.
func build(cfg *config.Config, deps *dependencies, m *metrics.Metrics, log *slog.Logger) (*supervisor.Supervisor, error) {
	var resolver check.Resolver = check.DNSResolver{}
	if cfg.Docker.UseAPI {
		resolver = check.NewAPIResolver(deps.docker)
	}
	log.Info("resolving container addresses", "via", resolverName(cfg.Docker.UseAPI))

	checks, err := check.Build(check.Deps{
		Config:     cfg,
		Resolver:   resolver,
		Store:      deps.store,
		LocalStore: deps.localStore,
		AppDB:      deps.appDB,
		RootDB:     deps.rootDB,
	})
	if err != nil {
		return nil, fmt.Errorf("building the checks: %w", err)
	}

	for _, c := range checks {
		log.Info("check enabled", "check", c.Name, "threshold", c.Threshold, "probes", len(c.Probes))
	}

	return supervisor.New(supervisor.Options{
		Checks:     checks,
		Docker:     deps.docker,
		Store:      deps.store,
		Dispatcher: deps.dispatcher,
		Metrics:    m,
		Whois:      whois.New(whois.Options{}),
		Clock:      supervisor.Realtime{},
		Log:        log,
		NotifyBans: cfg.Notify.OnBan,
	})
}

// settle gives the rest of the stack a head start. Probing a container that is
// still starting only spends error budget on a service nobody has broken.
func settle(ctx context.Context, delay time.Duration, log *slog.Logger) error {
	if delay <= 0 {
		return nil
	}
	log.Info("waiting for containers to settle", "delay", delay)

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitFor polls until probe succeeds or the context is cancelled.
func waitFor(ctx context.Context, log *slog.Logger, what string, probe func(context.Context) error) error {
	for attempt := 1; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, dependencyPoll)
		err := probe(attemptCtx)
		cancel()

		if err == nil {
			log.Info("dependency is available", "dependency", what, "attempts", attempt)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Only the first failure is worth an info line; after that it is noise
		// until it succeeds.
		if attempt == 1 {
			log.Info("waiting for dependency", "dependency", what, "err", err)
		} else {
			log.Debug("still waiting for dependency", "dependency", what, "attempt", attempt, "err", err)
		}

		select {
		case <-time.After(dependencyPoll):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// checkIPv6 verifies once, at startup, that a bridge configured for IPv6 also
// has a working route out.
//
// mailcow's docker-compose can enable IPv6 on the network. When it is enabled
// but the host cannot actually reach the v6 internet, delivery to v6-only
// exchangers fails in a way that is very hard to attribute weeks later. The
// shell checked this once for the same reason; it is not a recurring check.
func checkIPv6(ctx context.Context, cfg *config.Config, dispatcher *notify.Dispatcher, log *slog.Logger) {
	configured, err := probe.IPv6Configured(cfg.Mailcow.IPv6Network, probe.LocalAddrs)
	if err != nil {
		log.Warn("cannot determine whether IPv6 is configured", "err", err)
		return
	}
	if !configured {
		log.Debug("no local address in the configured IPv6 network, skipping the link check",
			"network", cfg.Mailcow.IPv6Network)
		return
	}

	if address := probe.NewIPv6Link(probe.IPv6Options{}).Address(ctx); address != "" {
		log.Info("IPv6 link is up", "address", address)
		return
	}
	if ctx.Err() != nil {
		return
	}

	const message = "enable_ipv6 is true in docker-compose.yml, but an IPv6 link " +
		"could not be established. Please verify your IPv6 connection."

	log.Error("IPv6 is enabled on the bridge but no link could be established")
	if dispatcher == nil {
		return
	}
	if err := dispatcher.Dispatch(ctx, notify.Alert{Service: "ipv6-config", Message: message}); err != nil {
		log.Error("cannot send the IPv6 notification", "err", err)
	}
}

// announceStart sends the "watchdog is up" notification, if one is wanted.
func announceStart(ctx context.Context, dispatcher *notify.Dispatcher, m *metrics.Metrics, log *slog.Logger) {
	if dispatcher == nil {
		m.ObserveNotification("disabled")
		return
	}
	err := dispatcher.Dispatch(ctx, notify.Alert{
		Service: "watchdog-mailcow",
		Message: "Watchdog started monitoring mailcow.",
	})
	if err != nil {
		log.Error("cannot send the startup notification", "err", err)
		m.ObserveNotification("failed")
		return
	}
	m.ObserveNotification("sent")
}

// newLogger builds the structured logger.
func newLogger(cfg config.Log) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func resolverName(useAPI bool) string {
	if useAPI {
		return "dockerapi"
	}
	return "dns"
}

func waitForMetrics(done chan error) error {
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return errors.New("the metrics server did not shut down")
	}
}
