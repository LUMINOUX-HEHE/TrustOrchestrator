package trustorchestrator

// ratelimit: token-bucket per key — the leaky shape (burst cap) bounds the
// short-term ceiling, the refill rate the sustained one. Each request or
// frame costs one token; when a bucket drains the key is denied. Every
// path is budgeted: the REST surface per token identity (api.go route
// middleware) and the mTLS watchdog wire per peer (fleet.go), so the wire
// cannot bypass the API's throttle.
// ponytail: fixed constants, not flags; add -limit-rate/-limit-burst when
// an operator asks.

import (
	"sync"
	"time"
)

const (
	apiRate  = 20.0 // tokens/s per API identity
	apiBurst = 40.0
	wireRate  = 1.0 // frames/s per mTLS peer; legit nodes send 1 per 30s
	wireBurst = 4.0
)

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

// allow grants one token to key, refilling by elapsed time first.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: time.Now()}
		l.buckets[key] = b
	} else {
		b.tokens += time.Since(b.last).Seconds() * l.rate
		b.last = time.Now()
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
