package worker

import (
	"testing"
	"time"
)

func TestHourlyAt(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 25, h, m, 0, 0, time.UTC) }
	for _, c := range []struct{ now, want time.Time }{
		{at(9, 0), at(9, 15)},
		{at(9, 15), at(10, 15)},
		{at(9, 59), at(10, 15)},
	} {
		if got := HourlyAt(15).Next(c.now); !got.Equal(c.want) {
			t.Errorf("Next(%v) = %v, want %v", c.now, got, c.want)
		}
	}
}

func TestScanJobsRetryOnceOnScanQueue(t *testing.T) {
	o := ScanArgs{}.InsertOpts()
	if o.Queue != QueueScan || o.MaxAttempts != 2 {
		t.Fatalf("%+v", o)
	}
}
