package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

func TestDailyAt(t *testing.T) {
	ict := time.FixedZone("ICT", 7*3600)
	for _, c := range []struct{ now, want time.Time }{
		{time.Date(2026, 10, 26, 7, 59, 0, 0, time.UTC), time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)},
		{time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC), time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)},
		{time.Date(2026, 10, 26, 23, 0, 0, 0, ict), time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)}, // 16:00 UTC
	} {
		if got := DailyAt(8).Next(c.now); !got.Equal(c.want) {
			t.Errorf("%v: %v, want %v", c.now, got, c.want)
		}
	}
}

func TestDispatchAndDigestJobs(t *testing.T) {
	user := uuid.New()
	env, db, _, scoped, orgs := sweepEnv(t,
		dbtest.Step{Prefix: "SELECT id, type, payload FROM outbox_event"},
		dbtest.Step{Prefix: "SELECT i.assignee_id, count(*)", Rows: [][]any{{user, 1}}},
		dbtest.Step{Prefix: "INSERT INTO outbox_event", Affected: 1},
	)
	if err := (DispatchNotificationsWorker{Env: env}).Work(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if n := len(db.Calls("SELECT id, type, payload FROM outbox_event")); n != 2 {
		t.Fatal("dispatch per org", n)
	}
	if (*scoped)[1] != orgs[0] || (*scoped)[2] != orgs[1] {
		t.Fatalf("scoping %v", *scoped)
	}
	if err := (SLADigestWorker{Env: env}).Work(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ins := db.Calls("INSERT INTO outbox_event")
	if len(ins) != 2 || ins[0].Args[1] != "sla.overdue" || *ins[0].Args[3].(*string) != "sla:"+user.String()+":2026-10-26" {
		t.Fatalf("%+v", ins)
	}

	// Per-org failures are reported; nil env cancels.
	env, _, _, _, _ = sweepEnv(t,
		dbtest.Step{Prefix: "SELECT id, type, payload FROM outbox_event", Err: errors.New("down")},
		dbtest.Step{Prefix: "SELECT i.assignee_id, count(*)", Err: errors.New("down")})
	if err := env.DispatchNotifications(context.Background()); err == nil {
		t.Fatal("dispatch error swallowed")
	}
	if err := env.SLADigest(context.Background()); err == nil {
		t.Fatal("digest error swallowed")
	}
	var cancel *river.JobCancelError
	for _, err := range []error{
		(DispatchNotificationsWorker{}).Work(context.Background(), nil),
		(SLADigestWorker{}).Work(context.Background(), nil),
	} {
		if !errors.As(err, &cancel) {
			t.Fatal(err)
		}
	}
	if (DispatchNotificationsArgs{}).Kind() != "dispatch_notifications" || (SLADigestArgs{}).Kind() != "sla_digest" ||
		(DispatchNotificationsArgs{}).InsertOpts().UniqueOpts.ByPeriod == 0 {
		t.Fatal("job contract")
	}
}
