package notify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

func pruneTx(db *dbtest.DB, orgs *[]uuid.UUID) TxFunc {
	return func(_ context.Context, org uuid.UUID, fn func(DB) error) error {
		*orgs = append(*orgs, org)
		return fn(db)
	}
}

// Batches continue while either table filled one, and stop at the cap.
func TestPruneOrgBatches(t *testing.T) {
	const call = "SELECT notifications, events FROM warden_prune_notifications"
	r := Retention{Read: 90 * 24 * time.Hour, Unread: 365 * 24 * time.Hour}
	cutoffs := func(args []any) error {
		if !args[0].(time.Time).Equal(now.Add(-r.Read)) || !args[1].(time.Time).Equal(now.Add(-r.Unread)) || args[2] != pruneBatch {
			return fmt.Errorf("args %v", args)
		}
		return nil
	}
	db := dbtest.New(t,
		dbtest.Step{Prefix: call, Args: cutoffs, Rows: [][]any{{int64(pruneBatch), int64(3)}}},
		dbtest.Step{Prefix: call, Rows: [][]any{{int64(10), int64(pruneBatch)}}},
		dbtest.Step{Prefix: call, Rows: [][]any{{int64(2), int64(0)}}},
	)
	var orgs []uuid.UUID
	notes, events, err := PruneOrg(context.Background(), pruneTx(db, &orgs), orgID, now, r)
	db.Done()
	if err != nil || notes != pruneBatch+12 || events != pruneBatch+3 {
		t.Fatal(notes, events, err)
	}
	for _, o := range orgs {
		if o != orgID {
			t.Fatal("pruned outside the org's scope", o)
		}
	}

	full := make([]dbtest.Step, maxPruneBatches)
	for i := range full {
		full[i] = dbtest.Step{Prefix: call, Rows: [][]any{{int64(pruneBatch), int64(0)}}}
	}
	db = dbtest.New(t, full...)
	if notes, _, err = PruneOrg(context.Background(), pruneTx(db, &orgs), orgID, now, r); err != nil || notes != maxPruneBatches*pruneBatch {
		t.Fatal(notes, err)
	}
	db.Done() // and no statement past the cap
}

func TestPruneOrgErrors(t *testing.T) {
	db := dbtest.New(t, dbtest.Step{Prefix: "SELECT notifications", Err: errDB})
	var orgs []uuid.UUID
	if _, _, err := PruneOrg(context.Background(), pruneTx(db, &orgs), orgID, now, Retention{Read: MinRetention, Unread: MinRetention}); err != errDB {
		t.Fatal(err)
	}
	db.Done()
	// A retention under a day (unset config) never reaches the database.
	for _, r := range []Retention{{}, {Read: time.Hour, Unread: 365 * 24 * time.Hour}, {Read: 90 * 24 * time.Hour, Unread: -time.Hour}} {
		db := dbtest.New(t)
		if _, _, err := PruneOrg(context.Background(), pruneTx(db, &orgs), orgID, now, r); err == nil {
			t.Fatalf("%+v accepted", r)
		}
		db.Done()
	}
}
