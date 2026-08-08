package trustorchestrator

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// AuditorLog is an auditor-operated append-only mirror of governance events
// (FR3.1). Each auditor runs its own log.
// ponytail: chain-integrity check only — the auditor has no council key, so
// signature verification stays with W2 (which does have it).
type AuditorLog struct {
	events []TrustEvent
	head   []byte
	algo   hashAlgo // link-digest algorithm; must match the mirrored timeline
}

// NewAuditorLog mirrors a chain built under the given link algorithm.
func NewAuditorLog(algo hashAlgo) *AuditorLog {
	return &AuditorLog{algo: algo}
}

func (a *AuditorLog) Mirror(e TrustEvent) {
	a.events = append(a.events, e)
	a.head = e.Hash()
}

func (a *AuditorLog) Verify() bool {
	for i, e := range a.events {
		if i == 0 && e.ParentHash != nil {
			return false
		}
		if i > 0 && !bytes.Equal(e.ParentHash, hashWith(a.algo, append(a.events[i-1].canonical(), a.events[i-1].Signature...))) {
			return false
		}
	}
	return true
}

func (a *AuditorLog) Head() []byte { return a.head }

// Policy is the operator-declared conformance surface (FR3.2).
// ponytail: one rule today — the docs' "<= K certs per identity per day".
// Extend the list when a second example policy exists.
type Policy struct {
	MaxIssuesPerIdentityPerWindow int `json:"max_issues_per_identity_per_window"`
}

// CheckPolicy returns human-readable violations found in the events.
func CheckPolicy(events []TrustEvent, pol Policy) []string {
	perID := map[string]int{}
	for _, e := range events {
		if e.Type != EvIssue {
			continue
		}
		var p issuePayload
		if json.Unmarshal(e.Payload, &p) == nil {
			perID[p.Identity]++
		}
	}
	var v []string
	for id, n := range perID {
		if n > pol.MaxIssuesPerIdentityPerWindow {
			v = append(v, fmt.Sprintf("%s: %d issues > %d", id, n, pol.MaxIssuesPerIdentityPerWindow))
		}
	}
	return v
}

// Escalation is an auditor-consensus score raise (FR3.3). Auditors can never
// execute recovery (P6): this API surface is the only auditor authority.
type Escalation struct {
	AuditorIDs []string
	Target     string
	Reason     string
}

// DetectEscalated implements the FR3.3 "force DETECTED" semantics: when >=
// minAuditors distinct auditor operators agree AND the target watchdog is
// genuinely alarmed, the ensemble fires even below its internal quorum.
// P6 holds structurally: this path raises detection only; the council alone
// executes recovery.
func DetectEscalated(scores []Score, esc Escalation, minAuditors int, threshold float64, quorum int) bool {
	if len(distinctIDs(esc.AuditorIDs)) >= minAuditors {
		for _, s := range scores {
			if s.NodeID == esc.Target && s.Score < threshold {
				return true
			}
		}
	}
	return Detect(scores, threshold, quorum)
}

func distinctIDs(ids []string) map[string]bool {
	d := map[string]bool{}
	for _, id := range ids {
		d[id] = true
	}
	return d
}
