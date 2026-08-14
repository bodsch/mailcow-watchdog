// Package notify delivers the watchdog's alerts by mail and webhook.
//
// It replaces watchdog.sh's notify_error, including its rules for building the
// subject and body, its fail2ban special case and its Redis-backed throttle.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// defaultBody is what the shell sent when a caller supplied no message: the
// event was a container restart and the operator is meant to go and look.
const defaultBody = "Service was restarted on %s, please check your mailcow installation."

// fail2banService is the one event whose subject and body are swapped: the
// interesting part is which address was banned, so that goes in the subject.
const fail2banService = "fail2ban"

// fail2banBody is the fixed body that accompanies a ban notification.
const fail2banBody = "Please see netfilter-mailcow for more details and triggered rules."

// Alert is one thing the watchdog wants to say.
type Alert struct {
	// Service is the event name, such as "nginx-mailcow" or "certcheck". It
	// appears in the subject and keys the throttle.
	Service string
	// Message replaces the default "service was restarted" body.
	Message string
	// Details is a probe transcript. When present it becomes the body, which is
	// how the shell used the /tmp/<service> files it had been appending to.
	Details string
	// Throttle suppresses repeats of the same Service within the window. Zero
	// means every alert is delivered.
	Throttle time.Duration
}

// Message is a rendered alert, ready for any transport.
type Message struct {
	Service string
	Subject string
	Body    string
}

// Notifier delivers a rendered message.
type Notifier interface {
	Send(ctx context.Context, msg Message) error
}

// Render turns an alert into a subject and body using the shell's rules.
//
// subjectPrefix is WATCHDOG_SUBJECT and now supplies the timestamp the shell got
// from $(date).
func Render(alert Alert, subjectPrefix string, now time.Time) Message {
	stamp := now.Format(time.UnixDate)

	body := fmt.Sprintf(defaultBody, stamp)
	if alert.Message != "" {
		body = stamp + " - " + alert.Message
	}

	subject := subjectPrefix + ": " + alert.Service
	if alert.Service == fail2banService {
		// The banned address is the headline, so it moves into the subject and
		// the body falls back to boilerplate.
		subject, body = body, fail2banBody
	}

	// A transcript wins over both, which is what the shell's
	//
	//	[ -f "/tmp/${1}" ] && BODY="/tmp/${1}"
	//
	// did — including for fail2ban, whose /tmp file held the whois record. That
	// line sat after the subject/body swap, so the boilerplate above only
	// survives when there is nothing better to say.
	if alert.Details != "" {
		body = alert.Details
	}

	return Message{Service: alert.Service, Subject: subject, Body: body}
}

// Multi fans an alert out to every configured channel.
//
// A channel that fails does not stop the others: losing the webhook must not
// cost the operator their mail.
type Multi struct {
	channels []Notifier
	log      *slog.Logger
}

// NewMulti returns a Notifier that writes to all of channels. Nil entries are
// skipped so callers can build the list conditionally.
func NewMulti(log *slog.Logger, channels ...Notifier) *Multi {
	if log == nil {
		log = slog.Default()
	}
	live := make([]Notifier, 0, len(channels))
	for _, channel := range channels {
		if channel != nil {
			live = append(live, channel)
		}
	}
	return &Multi{channels: live, log: log.With("component", "notify")}
}

// Enabled reports whether any channel is configured.
func (m *Multi) Enabled() bool { return len(m.channels) > 0 }

// Send implements Notifier.
func (m *Multi) Send(ctx context.Context, msg Message) error {
	var errs []error
	for _, channel := range m.channels {
		if err := channel.Send(ctx, msg); err != nil {
			m.log.Error("notification channel failed", "err", err, "service", msg.Service)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Reserver is the throttle backend, satisfied by store.Store.
type Reserver interface {
	// Reserve claims a slot for key, reporting whether the caller may proceed
	// and how long an existing reservation still has to run.
	Reserve(ctx context.Context, key string, ttl time.Duration) (bool, time.Duration, error)
}

// Dispatcher renders alerts and delivers them, applying the throttle.
type Dispatcher struct {
	notifier      Notifier
	reserver      Reserver
	subjectPrefix string
	now           func() time.Time
	log           *slog.Logger
}

// NewDispatcher wires the pieces together. A nil notifier disables delivery
// entirely, which is the state when neither WATCHDOG_NOTIFY_EMAIL nor
// WATCHDOG_NOTIFY_WEBHOOK is configured.
func NewDispatcher(notifier Notifier, reserver Reserver, subjectPrefix string, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	return &Dispatcher{
		notifier:      notifier,
		reserver:      reserver,
		subjectPrefix: subjectPrefix,
		now:           time.Now,
		log:           log.With("component", "notify"),
	}
}

// Dispatch renders and delivers an alert, honouring its throttle.
//
// A throttled alert is not an error: it is the mechanism working.
func (d *Dispatcher) Dispatch(ctx context.Context, alert Alert) error {
	if d.notifier == nil {
		return nil
	}

	if alert.Throttle > 0 && d.reserver != nil {
		allowed, wait, err := d.reserver.Reserve(ctx, alert.Service, alert.Throttle)
		if err != nil {
			// Failing open is the safer default: an unreachable Redis must not
			// silence alerts about the rest of the stack.
			d.log.Warn("cannot check the notification throttle, sending anyway",
				"err", err, "service", alert.Service)
		} else if !allowed {
			d.log.Info("notification suppressed by throttle",
				"service", alert.Service, "retry_in", wait)
			return nil
		}
	}

	return d.notifier.Send(ctx, Render(alert, d.subjectPrefix, d.now()))
}
