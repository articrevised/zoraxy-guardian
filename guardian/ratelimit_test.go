package guardian

import (
	"testing"
	"time"
)

func TestRateLimiterBurstThenRefill(t *testing.T) {
	rl := newRateLimiter(60, 3) // 1 token/sec, burst 3

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("burst %d should pass", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th immediate request should be limited")
	}

	// Force time forward by manipulating bucket directly to avoid sleeping.
	rl.mu.Lock()
	rl.buckets["1.2.3.4"].last = time.Now().Add(-2 * time.Second)
	rl.mu.Unlock()
	if !rl.allow("1.2.3.4") {
		t.Fatal("after refill, request should pass")
	}
}

func TestRateLimiterIsolatesKeys(t *testing.T) {
	rl := newRateLimiter(60, 1)
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
	if !rl.allow("k") {
		t.Fatal("min-bounded limiter should still allow at least one")
	}
}
