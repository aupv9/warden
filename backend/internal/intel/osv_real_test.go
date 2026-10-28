package intel

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
)

// TestOSVRealFeeds parses real OSV all.zip files when WARDEN_OSV_DIR points
// at a directory holding <ecosystem>.zip (as in the mirror's intel/osv/), and
// logs the counts, the time and the heap. Skipped otherwise (no network or
// large files in unit tests).
func TestOSVRealFeeds(t *testing.T) {
	dir := os.Getenv("WARDEN_OSV_DIR")
	if dir == "" {
		t.Skip("WARDEN_OSV_DIR not set")
	}
	for _, eco := range ecosystem.OSV {
		path := filepath.Join(dir, eco+".zip")
		f, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		start := time.Now()
		stop := make(chan struct{})
		peak := make(chan uint64)
		go func() {
			var m runtime.MemStats
			var max uint64
			tick := time.NewTicker(20 * time.Millisecond)
			defer tick.Stop()
			for {
				runtime.ReadMemStats(&m)
				max = maxU(max, m.HeapInuse)
				select {
				case <-stop:
					peak <- max
					return
				case <-tick.C:
				}
			}
		}()
		res, err := ParseOSVMalicious(f, fi.Size(), eco)
		elapsed := time.Since(start)
		close(stop)
		heap := <-peak
		f.Close()
		if err != nil {
			t.Fatalf("%s: %v", eco, err)
		}
		all := 0
		for _, p := range res.Packages {
			if p.AllVersions {
				all++
			}
		}
		t.Logf("%s: %d MB zip, %v, peak heap in use %d MB; advisories %d, packages %d (all versions %d), withdrawn %d, "+
			"unsupported %d, partial %d, other ecosystem %d, invalid %d %v, skipped entries %d, updated %s",
			eco, fi.Size()>>20, elapsed.Round(time.Millisecond), heap>>20, res.Advisories, len(res.Packages), all, res.Withdrawn,
			res.Unsupported, res.Partial, res.OtherEcosystem, res.Invalid, res.InvalidSamples, res.Skipped,
			res.Updated.Format(time.RFC3339))
		if res.Advisories == 0 || res.Invalid > 0 {
			t.Errorf("%s: unexpected result", eco)
		}
	}
}

func maxU(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
