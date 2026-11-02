package webhook

import (
	"testing"

	"github.com/aupv9/warden/backend/internal/metrics"
)

func TestCountDelivery(t *testing.T) {
	value := func(name, k, v string) float64 { return metrics.Value(name, map[string]string{k: v}) }
	for _, c := range []struct {
		o      outcome
		test   bool
		status string
		sent   float64 // notifications sent over the webhook channel
	}{
		{outcome{attempted: true, final: true}, false, "delivered", 1},
		{outcome{attempted: true, final: true}, true, "delivered", 0}, // a test is not a notification
		{outcome{attempted: true, result: Result{Error: ErrTimeout}}, false, "retrying", 0},
		{outcome{attempted: true, result: Result{Error: ErrHTTPStatus, StatusCode: 404}, final: true}, false, "failed", 0},
		{outcome{result: Result{Error: ErrDisabled}, final: true}, false, "failed", 0},
	} {
		before := value("warden_webhook_deliveries_total", "status", c.status)
		sent := value("warden_notifications_sent_total", "channel", "webhook")
		countDelivery(c.o, c.test)
		if value("warden_webhook_deliveries_total", "status", c.status) != before+1 {
			t.Errorf("%+v: %s not counted", c.o, c.status)
		}
		if got := value("warden_notifications_sent_total", "channel", "webhook") - sent; got != c.sent {
			t.Errorf("%+v: webhook notifications %v", c.o, got)
		}
	}
}
