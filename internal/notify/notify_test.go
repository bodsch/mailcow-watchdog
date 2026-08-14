package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var testClock = time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC)

// recorder is a Notifier that keeps what it was given.
type recorder struct {
	mu   sync.Mutex
	sent []Message
	err  error
}

func (r *recorder) Send(_ context.Context, msg Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, msg)
	return r.err
}

func (r *recorder) messages() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Message(nil), r.sent...)
}

func TestRenderDefaultBody(t *testing.T) {
	msg := Render(Alert{Service: "nginx-mailcow"}, "Watchdog ALERT", testClock)

	if msg.Subject != "Watchdog ALERT: nginx-mailcow" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	if !strings.HasPrefix(msg.Body, "Service was restarted on ") {
		t.Errorf("Body = %q, want the default restart sentence", msg.Body)
	}
	if !strings.Contains(msg.Body, "please check your mailcow installation") {
		t.Errorf("Body = %q", msg.Body)
	}
}

func TestRenderCustomMessage(t *testing.T) {
	msg := Render(Alert{
		Service: "mysql_repl_checks",
		Message: "Please check the SQL replication status",
	}, "Watchdog ALERT", testClock)

	if msg.Subject != "Watchdog ALERT: mysql_repl_checks" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	if !strings.HasSuffix(msg.Body, " - Please check the SQL replication status") {
		t.Errorf("Body = %q, want the timestamp followed by the message", msg.Body)
	}
}

// A probe transcript is more useful than the generic sentence, which is why the
// shell used the contents of /tmp/<service> when it had any.
func TestRenderPrefersTheTranscript(t *testing.T) {
	msg := Render(Alert{
		Service: "nginx-mailcow",
		Message: "ignored once there is a transcript",
		Details: "HTTP CRITICAL: connection refused",
	}, "Watchdog ALERT", testClock)

	if msg.Body != "HTTP CRITICAL: connection refused" {
		t.Errorf("Body = %q, want the transcript", msg.Body)
	}
}

// fail2ban is the one event whose subject and body are swapped: the banned
// address is the headline.
func TestRenderFail2banSwapsSubjectAndBody(t *testing.T) {
	msg := Render(Alert{
		Service: "fail2ban",
		Message: "IP ban: 198.51.100.7",
	}, "Watchdog ALERT", testClock)

	if !strings.Contains(msg.Subject, "IP ban: 198.51.100.7") {
		t.Errorf("Subject = %q, want the ban in the subject", msg.Subject)
	}
	if msg.Body != fail2banBody {
		t.Errorf("Body = %q, want %q", msg.Body, fail2banBody)
	}
}

// The shell wrote the whois record to /tmp/fail2ban before notifying, and its
// `[ -f "/tmp/${1}" ] && BODY=...` line ran after the subject/body swap. So the
// registry record, not the boilerplate, is what the operator receives.
func TestRenderFail2banPrefersTheWhoisRecord(t *testing.T) {
	msg := Render(Alert{
		Service: "fail2ban",
		Message: "IP ban: 198.51.100.7",
		Details: "netname: EXAMPLE-NET\ncountry: DE",
	}, "Watchdog ALERT", testClock)

	if !strings.Contains(msg.Subject, "IP ban: 198.51.100.7") {
		t.Errorf("Subject = %q, want the ban in the subject", msg.Subject)
	}
	if !strings.Contains(msg.Body, "netname: EXAMPLE-NET") {
		t.Errorf("Body = %q, want the whois record", msg.Body)
	}
}

// stubReserver lets a test decide whether an alert gets through.
type stubReserver struct {
	allow bool
	wait  time.Duration
	err   error
	calls int
}

func (s *stubReserver) Reserve(context.Context, string, time.Duration) (bool, time.Duration, error) {
	s.calls++
	return s.allow, s.wait, s.err
}

func TestDispatcherThrottle(t *testing.T) {
	tests := []struct {
		name      string
		throttle  time.Duration
		reserver  *stubReserver
		wantSends int
		wantCalls int
	}{
		{
			name:      "no throttle configured",
			throttle:  0,
			reserver:  &stubReserver{allow: true},
			wantSends: 1,
			wantCalls: 0,
		},
		{
			name:      "slot is free",
			throttle:  10 * time.Minute,
			reserver:  &stubReserver{allow: true},
			wantSends: 1,
			wantCalls: 1,
		},
		{
			name:      "slot is taken",
			throttle:  10 * time.Minute,
			reserver:  &stubReserver{allow: false, wait: 4 * time.Minute},
			wantSends: 0,
			wantCalls: 1,
		},
		{
			// An unreachable Redis must not silence alerts about the rest of
			// the stack.
			name:      "throttle backend is broken",
			throttle:  10 * time.Minute,
			reserver:  &stubReserver{err: errors.New("connection refused")},
			wantSends: 1,
			wantCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			d := NewDispatcher(rec, tc.reserver, "Watchdog ALERT", nil)

			err := d.Dispatch(context.Background(), Alert{
				Service:  "certcheck",
				Throttle: tc.throttle,
			})
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if got := len(rec.messages()); got != tc.wantSends {
				t.Errorf("sent %d messages, want %d", got, tc.wantSends)
			}
			if tc.reserver.calls != tc.wantCalls {
				t.Errorf("consulted the throttle %d times, want %d", tc.reserver.calls, tc.wantCalls)
			}
		})
	}
}

func TestDispatcherWithoutChannelsIsQuiet(t *testing.T) {
	d := NewDispatcher(nil, nil, "Watchdog ALERT", nil)
	if err := d.Dispatch(context.Background(), Alert{Service: "nginx-mailcow"}); err != nil {
		t.Errorf("Dispatch with no notifier should be a no-op, got %v", err)
	}
}

// Losing the webhook must not cost the operator their mail.
func TestMultiKeepsGoingAfterAFailure(t *testing.T) {
	broken := &recorder{err: errors.New("webhook is down")}
	working := &recorder{}

	multi := NewMulti(nil, broken, nil, working)
	if !multi.Enabled() {
		t.Error("Enabled() = false, want true")
	}

	err := multi.Send(context.Background(), Message{Service: "nginx-mailcow"})
	if err == nil {
		t.Error("Send should report the failing channel")
	}
	if len(working.messages()) != 1 {
		t.Error("the working channel should still have been used")
	}
}

func TestMultiWithoutChannels(t *testing.T) {
	if NewMulti(nil).Enabled() {
		t.Error("Enabled() = true for an empty Multi")
	}
}

// The shell escaped only sed's own metacharacters, so a quote or a newline in a
// transcript produced a body that was no longer valid JSON.
func TestExpandProducesValidJSON(t *testing.T) {
	template := `{"text":"$SUBJECT","attachments":[{"text":"${BODY}"}]}`
	msg := Message{
		Subject: `Watchdog ALERT: container "nginx" failed`,
		Body:    "line one\nline two\twith a tab and a \\ backslash",
	}

	got := Expand(template, msg)

	var parsed struct {
		Text        string `json:"text"`
		Attachments []struct {
			Text string `json:"text"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("Expand produced invalid JSON: %v\n%s", err, got)
	}
	if parsed.Text != msg.Subject {
		t.Errorf("subject round-tripped as %q, want %q", parsed.Text, msg.Subject)
	}
	if len(parsed.Attachments) != 1 || parsed.Attachments[0].Text != msg.Body {
		t.Errorf("body round-tripped as %+v, want %q", parsed.Attachments, msg.Body)
	}
}

// Both spellings of the placeholders were supported by the shell's sed.
func TestExpandHandlesBothPlaceholderForms(t *testing.T) {
	got := Expand(`{"a":"$SUBJECT","b":"${SUBJECT}","c":"$BODY","d":"${BODY}"}`,
		Message{Subject: "S", Body: "B"})

	want := `{"a":"S","b":"S","c":"B","d":"B"}`
	if got != want {
		t.Errorf("Expand = %s, want %s", got, want)
	}
}

// HTML escaping would be valid JSON but makes alerts unpleasant to read in a
// chat client.
func TestExpandDoesNotHTMLEscape(t *testing.T) {
	got := Expand(`{"t":"$SUBJECT"}`, Message{Subject: "a < b & c > d"})
	if !strings.Contains(got, "a < b & c > d") {
		t.Errorf("Expand = %s, want the characters left alone", got)
	}
}

func TestWebhookPostsTheTemplate(t *testing.T) {
	var got struct {
		body        string
		contentType string
	}
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		got.body = string(buf[:n])
		got.contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhook(srv.URL, `{"text":"$SUBJECT"}`, nil)
	if err := sender.Send(context.Background(), Message{Subject: "Watchdog ALERT: nginx-mailcow"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got.contentType)
	}
	if !strings.Contains(got.body, "Watchdog ALERT: nginx-mailcow") {
		t.Errorf("body = %q", got.body)
	}
}

func TestWebhookReportsAnErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sender := NewWebhook(srv.URL, `{"text":"$SUBJECT"}`, nil)
	if err := sender.Send(context.Background(), Message{Subject: "x"}); err == nil {
		t.Error("Send should report a 400")
	}
}

func TestNewWebhookNeedsBothURLAndTemplate(t *testing.T) {
	if NewWebhook("", `{"t":"$SUBJECT"}`, nil) != nil {
		t.Error("a webhook without a URL should not be constructed")
	}
	if NewWebhook("https://example.org/hook", "", nil) != nil {
		t.Error("a webhook without a template should not be constructed")
	}
}
