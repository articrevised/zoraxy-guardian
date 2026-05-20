package guardian

import (
	"testing"
	"time"
)

func TestRateLimiterBurstThenRefill(t *testing.T) {
	rl := newRateLimiter(60, 3) // 1 token/sec, burst 3
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("burst %d should pass", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th immediate request should be limited")
	}

	rl.mu.Lock()
	rl.buckets["1.2.3.4"].last = time.Now().Add(-2 * time.Second)
	rl.mu.Unlock()
	if !rl.allow("1.2.3.4") {
		t.Fatal("after refill, request should pass")
	}
}

func TestRateLimiterIsolatesKeys(t *testing.T) {
	rl := newRateLimiter(60, 1)
	defer rl.Stop()
	if !rl.allow("a") {
		t.Fatal("first a should pass")
	}
	if rl.allow("a") {
		t.Fatal("second a should be limited")
	}
	if !rl.allow("b") {
		t.Fatal("b should pass independently")
	}
}

func TestRateLimiterMinBounds(t *testing.T) {
	rl := newRateLimiter(0, 0)
	defer rl.Stop()
	if !rl.allow("k") {
		t.Fatal("min-bounded limiter should still allow at least one")
	}
}

func TestRateLimiterSweepEvictsIdleBuckets(t *testing.T) {
	rl := newRateLimiter(60, 1)
	defer rl.Stop()
	rl.allow("old-key")
	rl.allow("recent-key")

	// Mark old-key as idle past TTL.
	rl.mu.Lock()
	rl.buckets["old-key"].last = time.Now().Add(-2 * bucketIdleTTL)
	rl.mu.Unlock()

	rl.sweep(time.Now())

	rl.mu.Lock()
	_, oldExists := rl.buckets["old-key"]
	_, recentExists := rl.buckets["recent-key"]
	rl.mu.Unlock()

	if oldExists {
		t.Error("idle bucket should have been swept")
	}
	if !recentExists {
		t.Error("fresh bucket should remain")
	}
}
