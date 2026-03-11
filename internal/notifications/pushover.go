package notifications

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
	resp, err := p.client.PostForm(p.endpoint, url.Values{
		"token":    {p.apiToken},
		"user":     {p.userKey},
		"title":    {title},
		"message":  {message},
		"priority": {fmt.Sprintf("%d", priority)},
	})
	if err != nil {
		return fmt.Errorf("pushover request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pushover returned status %d", resp.StatusCode)
	}

	logging.Logger().Info("pushover notification sent",
		zap.String("title", title),
	)
	return nil
}

// NoopNotifier discards all notifications. Used when Pushover is not configured.
type NoopNotifier struct{}

func (n *NoopNotifier) Send(_ context.Context, _, _ string, _ int) error { return nil }
