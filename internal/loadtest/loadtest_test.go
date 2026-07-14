package loadtest

import (
	"sync"
	"testing"
	"time"
)

// TestLoadEvaluateP99Under50ms runs the gRPC Evaluate load test with 16
// workers x 200 requests each and asserts p99 < 50ms on the in-process OPA +
// in-memory velocity path. This is the Stage 10 acceptance criterion.
//
// Skipped in short mode and under the race detector (which adds 2-10x
// overhead and would make the p99 budget meaningless). The test serializes
// via a mutex to avoid contention with other packages inflating p99.
func TestLoadEvaluateP99Under50ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}
	if isRace {
		t.Skip("skipping load test under race detector")
	}
	loadSerial.Lock()
	defer loadSerial.Unlock()
	Run(t, 16, 200, 50*time.Millisecond)
}

// TestLoadEvaluateP99Under50msSmall is a smaller variant (4 workers x 50
// requests) that runs quickly even on slow CI and still validates the p99
// budget on a representative sample.
func TestLoadEvaluateP99Under50msSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}
	if isRace {
		t.Skip("skipping load test under race detector")
	}
	loadSerial.Lock()
	defer loadSerial.Unlock()
	Run(t, 4, 50, 50*time.Millisecond)
}

var loadSerial sync.Mutex

// isRace is true when built with -race. The race detector is detected via
// runtime/coordinator: there is no public API, so we use the fact that the
// race detector enables a specific build tag.
var isRace = raceEnabled