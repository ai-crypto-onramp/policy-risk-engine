package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Notifier notifies downstream services (the Transaction Orchestrator) when a
// review is resolved so the saga can resume. It posts the resolved Item to
// TX_ORCHESTRATOR_WEBHOOK_URL with an idempotency key equal to the decision_id.
type Notifier struct {
	url    string
	client *http.Client
}

// NewNotifier builds a Notifier from env. When TX_ORCHESTRATOR_WEBHOOK_URL is
// unset it returns a no-op notifier (Enabled() == false).
func NewNotifier() *Notifier {
	return &Notifier{
		url:    os.Getenv("TX_ORCHESTRATOR_WEBHOOK_URL"),
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Enabled reports whether a webhook URL is configured.
func (n *Notifier) Enabled() bool { return n != nil && n.url != "" }

// NotifyResolution posts the resolved item to the Transaction Orchestrator.
// It is best-effort: transient errors are returned but do not block the
// resolution itself. The webhook is retried up to 3 times on 5xx / network
// errors with exponential backoff (100ms, 200ms, 400ms).
func (n *Notifier) NotifyResolution(ctx context.Context, item Item) error {
	if n == nil || !n.Enabled() {
		return nil
	}
	if item.Status != StatusResolved {
		return errors.New("notifier: item is not resolved")
	}
	body, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	var lastErr error
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", item.DecisionID)
		resp, err := n.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return nil
		}
		if resp.StatusCode/100 == 4 {
			return fmt.Errorf("orchestrator webhook rejected: status %d", resp.StatusCode)
		}
		lastErr = fmt.Errorf("orchestrator webhook status %d", resp.StatusCode)
	}
	return lastErr
}