package trustorchestrator

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
)

// Watchdog kinds (FR2.1).
const (
	WDIssuanceRate     = "rate_cusum"
	WDLogIntegrity     = "log_integrity"
	WDGraphAnomaly     = "graph_anomaly"
	WDExternalProbe    = "external_probe"
	WDBehaviorBaseline = "behavior_baseline"
)

// Watchdog runs one detector type over timeline batches (FR2.2).
// W1/W3/W5 share the CUSUM core; W2 = chain gap locator; W4 = mirror
// cross-check. mu0/delta/h come from TrustOps calibration, never by hand.
type Watchdog struct {
	mu       sync.Mutex
	ID       string
	Kind     string
	mu0      float64
	delta    float64
	h        float64
	cusum    *CUSUM
	tl       *Timeline          // W2/W4
	log      *AuditorLog        // W4: live auditor mirror head
	perID    map[string]*CUSUM  // W5: per-identity baselines
	baseline map[string]float64 // W5: learned mu0 per known identity
	firstIdx int                // first event index of the current batch
	badStart int                // earliest suspicious index (evidence anchor)
	checked  int                // W2: events verified so far
	cycles   int                // W2: full-verify cadence counter
	cached   *Score             // one score per batch: Score() is idempotent
}

func NewWatchdog(id, kind string, mu0, delta, h float64, tl *Timeline, log *AuditorLog) *Watchdog {
	return NewWatchdogBaseline(id, kind, mu0, delta, h, tl, log, nil)
}

// NewWatchdogBaseline additionally seeds W5 with known identities (mu0 per
// identity) so steady legitimate traffic never alarms; an identity absent
// from the baseline starts at mu0=0 — its appearance is the anomaly.
func NewWatchdogBaseline(id, kind string, mu0, delta, h float64, tl *Timeline, log *AuditorLog, baseline map[string]float64) *Watchdog {
	w := &Watchdog{
		ID: id, Kind: kind, mu0: mu0, delta: delta, h: h,
		tl: tl, log: log, perID: map[string]*CUSUM{}, baseline: baseline,
		badStart: -1, checked: -1,
	}
	if kind == WDIssuanceRate || kind == WDGraphAnomaly {
		w.cusum = NewCUSUM(mu0, delta, h)
	}
	return w
}

// ObserveBatch feeds one 30s cycle of events; updates detector state. W2/W4
// are stateless per batch (they read the timeline/mirror at Score time).
func (w *Watchdog) ObserveBatch(events []TrustEvent, firstIdx int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cached = nil
	w.firstIdx = firstIdx
	issues, edges := 0, 0
	perID := map[string]int{}
	for _, e := range events {
		if e.Type != EvIssue {
			continue
		}
		issues++
		var p issuePayload
		if json.Unmarshal(e.Payload, &p) != nil {
			continue
		}
		if p.Identity != "" {
			perID[p.Identity]++
		}
		if p.Via != "" {
			edges++
		}
	}
	switch w.Kind {
	case WDIssuanceRate:
		w.cusum.Observe(float64(issues))
		w.observeShift(w.cusum, firstIdx)
	case WDGraphAnomaly:
		w.cusum.Observe(float64(edges))
		w.observeShift(w.cusum, firstIdx)
	case WDBehaviorBaseline:
		for id, n := range perID {
			c := w.perID[id]
			if c == nil {
				mu0 := w.baseline[id] // 0 for unseen identities: appearance is the anomaly
				c = NewCUSUM(mu0, w.delta, w.h)
				w.perID[id] = c
			}
			c.Observe(float64(n))
			w.observeShift(c, firstIdx)
		}
	}
}

// observeShift records the change-point start: the first batch where the
// drift went from zero to positive. This is the rollback anchor (W3's
// "anomaly start", architecture §5.1), not the alarming batch.
func (w *Watchdog) observeShift(c *CUSUM, firstIdx int) {
	if c.S > 0 && w.badStart < 0 {
		w.badStart = firstIdx
	}
}

// Score emits the output contract (FR2.2). Low score = bad; evidence names
// the trigger and carries the rollback anchor. Idempotent: the same score
// is returned for one batch no matter how often Score is called, so W2's
// verify-cadence counters advance exactly once per batch. ponytail: p-value
// is a placeholder (0.01 on alarm) — a real distribution fit is calibration
// work, not detector logic.
func (w *Watchdog) Score() Score {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cached != nil {
		return *w.cached
	}
	s := w.computeScore()
	w.cached = &s
	return s
}

func (w *Watchdog) computeScore() Score {
	s := Score{NodeID: w.ID, PValue: 1.0}
	alarm := false
	switch w.Kind {
	case WDIssuanceRate, WDGraphAnomaly:
		alarm = w.cusum.Alarmed()
		if alarm {
			s.Evidence = []byte(fmt.Sprintf(`{"bad_index":%d,"S":%.2f}`, w.badStart, w.cusum.S))
		}
	case WDLogIntegrity:
		// O(1) delta-verify of new events each cycle (parent link + sig);
		// full linear re-scan every 10 cycles catches tampering of older
		// history. ponytail: cadence is the audit budget; a real W2 runs the
		// full scan on a background goroutine.
		w.cycles++
		if w.checked < 0 {
			w.checked = 0
		}
		bad := -1
		if w.cycles%10 == 0 {
			bad = w.tl.LocateBadEvent()
		} else {
			for i := w.checked; i < len(w.tl.events); i++ {
				e := w.tl.events[i]
				if i > 0 && !bytes.Equal(e.ParentHash, w.tl.digestEvent(w.tl.events[i-1])) {
					bad = i
					break
				}
				if !ed25519.Verify(w.tl.pub, e.canonical(), e.Signature) {
					bad = i
					break
				}
			}
		}
		if bad >= 0 {
			alarm = true
			w.badStart = bad
			s.Evidence = []byte(fmt.Sprintf(`{"bad_index":%d}`, bad))
		} else {
			w.checked = len(w.tl.events)
		}
	case WDExternalProbe:
		head := w.tl.Head()
		if w.log != nil && !bytes.Equal(head, w.log.Head()) {
			alarm = true
			w.badStart = len(w.log.events) // first event the attacker failed to mirror
			s.Evidence = []byte(fmt.Sprintf(`{"bad_index":%d,"local":%x,"mirror":%x}`, w.badStart, head, w.log.Head()))
		}
	case WDBehaviorBaseline:
		for id, c := range w.perID {
			if c.Alarmed() {
				alarm = true
				s.Evidence = []byte(fmt.Sprintf(`{"bad_index":%d,"identity":%q,"S":%.2f}`, w.badStart, id, c.S))
				break
			}
		}
	}
	if alarm {
		s.Score, s.PValue = 0, 0.01
	} else {
		s.Score = 100
	}
	return s
}
