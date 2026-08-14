package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// webhookTimeout bounds one POST.
const webhookTimeout = 10 * time.Second

// WebhookSender posts a rendered alert to an HTTP endpoint.
//
// The body is an operator-supplied JSON template with $SUBJECT and $BODY
// placeholders, which is how mailcow lets people wire the watchdog into Slack,
// Matrix, ntfy and the like.
type WebhookSender struct {
	url      string
	template string
	client   *http.Client
	log      *slog.Logger
}

// NewWebhook returns a webhook notifier, or nil when no URL is configured.
func NewWebhook(url, template string, log *slog.Logger) *WebhookSender {
	if url == "" || template == "" {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	return &WebhookSender{
		url:      url,
		template: template,
		client:   &http.Client{Timeout: webhookTimeout},
		log:      log.With("component", "notify.webhook"),
	}
}

// Send implements Notifier.
func (w *WebhookSender) Send(ctx context.Context, msg Message) error {
	body := Expand(w.template, msg)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("building the webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to the webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("the webhook answered %s", resp.Status)
	}

	w.log.Info("sent notification using webhook", "service", msg.Service)
	return nil
}

// Expand substitutes the placeholders in an operator's JSON template.
//
// watchdog.sh did this with sed and escaped only the characters sed itself would
// have misread. A subject containing a double quote, a backslash or a newline —
// all of which appear in probe transcripts — therefore produced a body that was
// no longer valid JSON, and the webhook silently rejected it. The values are
// JSON-escaped here instead, because that is what a placeholder inside a JSON
// string literal actually requires.
func Expand(template string, msg Message) string {
	replacer := strings.NewReplacer(
		"${SUBJECT}", jsonEscape(msg.Subject),
		"$SUBJECT", jsonEscape(msg.Subject),
		"${BODY}", jsonEscape(msg.Body),
		"$BODY", jsonEscape(msg.Body),
	)
	return replacer.Replace(template)
}

// jsonEscape renders a value as it would appear inside a JSON string, without
// the surrounding quotes.
func jsonEscape(value string) string {
	var buf bytes.Buffer

	encoder := json.NewEncoder(&buf)
	// The default encoder would turn <, > and & into < and friends, which
	// is valid JSON but makes the alert unpleasant to read in a chat client.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return ""
	}

	quoted := strings.TrimRight(buf.String(), "\n")
	return strings.TrimSuffix(strings.TrimPrefix(quoted, `"`), `"`)
}
