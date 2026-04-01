package notifications

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
	"go.uber.org/zap"
)

const pushoverEndpoint = "https://api.pushover.net/1/messages.json"

// Notifier sends alert messages. Implementations must be safe for concurrent use.
type Notifier interface {
	Send(ctx context.Context, title, message string, priority int) error
}

// PushoverNotifier sends notifications via the Pushover API.
type PushoverNotifier struct {
	apiToken string
	userKey  string
	client   *http.Client
	endpoint string // overridable for testing; defaults to pushoverEndpoint
}

// NewPushoverNotifier creates a Pushover notifier with the given credentials.
func NewPushoverNotifier(apiToken, userKey string) *PushoverNotifier {
	return &PushoverNotifier{
		apiToken: apiToken,
		userKey:  userKey,
		endpoint: pushoverEndpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: safenet.SafeDialer(10 * time.Second).DialContext,
			},
		},
	}
}

// Send posts a notification to the Pushover API.
func (p *PushoverNotifier) Send(ctx context.Context, title, message string, priority int) error {
	form := url.Values{
		"token":    {p.apiToken},
		"user":     {p.userKey},
		"title":    {title},
		"message":  {message},
		"priority": {fmt.Sprintf("%d", priority)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build pushover request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("pushover request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logging.Logger().Warn("pushover response close failed", zap.Error(err))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if readErr != nil {
			return fmt.Errorf("read pushover error response: %w", readErr)
		}
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			return fmt.Errorf("pushover returned status %d", resp.StatusCode)
		}
		return fmt.Errorf("pushover returned status %d: %s", resp.StatusCode, msg)
	}

	logging.Logger().Info("pushover notification sent",
		zap.String("title", title),
	)
	return nil
}

// NoopNotifier discards all notifications. Used when Pushover is not configured.
type NoopNotifier struct{}

func (n *NoopNotifier) Send(_ context.Context, _, _ string, _ int) error { return nil }
