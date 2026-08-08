package trustorchestrator

// Token bucket: burst holds, the (burst+1)th is denied, elapsed time
// refills deterministically (clock rewound, no sleeps), keys are isolated,
// and the gateway answers 429 once a token identity drains.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	l := newLimiter(10, 3)
	for i := 0; i < 3; i++ {
		if !l.allow("k") {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if l.allow("k") {
		t.Fatal("4th request inside the burst must be denied")
	}
	l.mu.Lock()
	l.buckets["k"].last = time.Now().Add(-time.Second)
	l.mu.Unlock()
	if !l.allow("k") {
		t.Fatal("refill after 1s at rate 10 must grant at least one token")
	}
}

func TestLimiterPerKeyIsolation(t *testing.T) {
	l := newLimiter(1, 2)
	if !l.allow("a") || !l.allow("a") {
		t.Fatal("a burst of 2")
	}
	if l.allow("a") {
		t.Fatal("a drained")
	}
	if !l.allow("b") {
		t.Fatal("b must have its own budget")
	}
}

func TestAPIRateLimit429(t *testing.T) {
	dir := t.TempDir()
	gw, token := newTestGateway(t, dir)
	gw.apiLimiter = newLimiter(0, 1) // no refill, burst 1: the second request is denied
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()
	get := func() int {
		req, _ := http.NewRequest("GET", srv.URL+"/v1/orgs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if got := get(); got != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", got)
	}
	if got := get(); got != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", got)
	}
}
