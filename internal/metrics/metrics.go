// Package metrics exposes the watchdog's own state to Prometheus.
//
// The shell watchdog published health levels to Redis for the mailcow UI and
// nothing else, so an operator could see that a service was unhealthy but not
// how often, how long its probes took, or how many restarts the watchdog had
// already issued. The Redis log is still written unchanged; these metrics are in
// addition to it.
package metrics

import (
	"bodsch.me/mailcow-watchdog/internal/health"
	"github.com/prometheus/client_golang/prometheus"
)

// namespace prefixes every metric.
const namespace = "mailcow_watchdog"

// Metrics holds the collectors. Construct it with New and register it once.
type Metrics struct {
	healthPercent *prometheus.GaugeVec
	healthPoints  *prometheus.GaugeVec
	threshold     *prometheus.GaugeVec

	probeTotal    *prometheus.CounterVec
	probeDuration *prometheus.HistogramVec

	checkDeaths *prometheus.CounterVec
	restarts    *prometheus.CounterVec
	events      *prometheus.CounterVec

	notifications *prometheus.CounterVec

	paused prometheus.Gauge
	info   *prometheus.GaugeVec
}

// New builds the collectors and registers them with reg.
func New(reg prometheus.Registerer, version string) *Metrics {
	m := &Metrics{
		healthPercent: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "check_health_percent",
			Help:      "Remaining health of a check as a percentage of its threshold.",
		}, []string{"check"}),

		healthPoints: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "check_health_points",
			Help:      "Remaining error budget of a check, in error points.",
		}, []string{"check"}),

		threshold: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "check_threshold_points",
			Help:      "Configured error budget of a check, in error points.",
		}, []string{"check"}),

		probeTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "probe_total",
			Help:      "Probe executions by outcome.",
		}, []string{"check", "probe", "status"}),

		probeDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "probe_duration_seconds",
			Help:      "Probe latency.",
			// The buckets straddle the ten second probe timeout, so a probe
			// that is merely slow is distinguishable from one that timed out.
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"check", "probe"}),

		checkDeaths: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "check_exhausted_total",
			Help:      "Times a check spent its whole error budget and reported its service dead.",
		}, []string{"check"}),

		restarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "container_restarts_total",
			Help:      "Container restarts issued through the dockerapi, by outcome.",
		}, []string{"container", "result"}),

		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "events_total",
			Help:      "Events raised by checks, by the action the supervisor took.",
		}, []string{"event", "action"}),

		notifications: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "notifications_total",
			Help:      "Notification attempts by outcome.",
		}, []string{"result"}),

		paused: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "paused",
			Help:      "1 while all checks are paused, for example because the dockerapi is unreachable.",
		}),

		info: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "build_info",
			Help:      "Build information, always 1.",
		}, []string{"version"}),
	}

	reg.MustRegister(
		m.healthPercent, m.healthPoints, m.threshold,
		m.probeTotal, m.probeDuration,
		m.checkDeaths, m.restarts, m.events,
		m.notifications, m.paused, m.info,
	)

	m.info.WithLabelValues(version).Set(1)
	return m
}

// ObserveHealth publishes a check's health after a round.
func (m *Metrics) ObserveHealth(check string, s health.Snapshot) {
	m.healthPercent.WithLabelValues(check).Set(float64(s.Percent))
	m.healthPoints.WithLabelValues(check).Set(float64(s.Remaining))
	m.threshold.WithLabelValues(check).Set(float64(s.Threshold))
}

// ObserveProbe records one probe execution.
func (m *Metrics) ObserveProbe(check, probe string, status health.Status, seconds float64) {
	m.probeTotal.WithLabelValues(check, probe, status.String()).Inc()
	m.probeDuration.WithLabelValues(check, probe).Observe(seconds)
}

// ObserveExhausted records that a check spent its whole budget.
func (m *Metrics) ObserveExhausted(check string) {
	m.checkDeaths.WithLabelValues(check).Inc()
}

// ObserveRestart records a container restart attempt. Outcomes are "restarted",
// "skipped" and "failed".
func (m *Metrics) ObserveRestart(container, result string) {
	m.restarts.WithLabelValues(container, result).Inc()
}

// ObserveEvent records how the supervisor handled an event.
func (m *Metrics) ObserveEvent(event, action string) {
	m.events.WithLabelValues(event, action).Inc()
}

// ObserveNotification records a delivery attempt. Outcomes are "sent",
// "throttled", "failed" and "disabled".
func (m *Metrics) ObserveNotification(result string) {
	m.notifications.WithLabelValues(result).Inc()
}

// SetPaused publishes whether the checks are currently held.
func (m *Metrics) SetPaused(paused bool) {
	m.paused.Set(boolToFloat(paused))
}

// InitCheck publishes a check's configured threshold before its first round, so
// the metric exists from startup rather than appearing minutes later.
func (m *Metrics) InitCheck(check string, threshold int) {
	m.threshold.WithLabelValues(check).Set(float64(threshold))
	m.healthPoints.WithLabelValues(check).Set(float64(threshold))
	m.healthPercent.WithLabelValues(check).Set(float64(health.Percent(threshold, threshold)))
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
