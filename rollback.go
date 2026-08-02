package trustorchestrator

import (
	"encoding/json"
	"strings"
)

// Rollback forks the timeline at the last verified good checkpoint and
// re-folds (FR5.1). The original chain is preserved by the caller as
// evidence. A compromise from genesis rolls back to the empty trust state.
func Rollback(tl *Timeline, badIdx int) (*Timeline, error) {
	if badIdx <= 0 {
		return NewTimeline(tl.key), nil
	}
	return tl.Fork(tl.events[badIdx-1].Hash())
}

// InvalidationSet computes the blast radius (FR5.2, P5): certs created in
// the bad window plus everything reachable from them through trust edges.
// Reachability follows via-edges only — an identity is a seed only when the
// bad event is about the identity itself, never a supernode that pulls in
// all of the identity's other certs (that would blow the scope; §5.6).
func InvalidationSet(tl *Timeline, badIdx int) (certs, identities map[string]bool) {
	g := BuildGraph(tl)
	certs, identities = map[string]bool{}, map[string]bool{}
	seeds := map[string]bool{}
	for _, e := range tl.events[badIdx:] {
		var p issuePayload
		if e.Type == EvIssue && json.Unmarshal(e.Payload, &p) == nil {
			seeds["cert:"+p.CertID] = true
			identities[p.Identity] = true
		}
		if e.Type == EvRevoke {
			var r struct {
				CertID string `json:"cert_id"`
			}
			if json.Unmarshal(e.Payload, &r) == nil {
				seeds["cert:"+r.CertID] = true
			}
		}
	}
	for s := range seeds {
		for _, node := range g.Reachable(s) {
			if strings.HasPrefix(node, "cert:") {
				certs[strings.TrimPrefix(node, "cert:")] = true
			}
		}
	}
	return certs, identities
}

// VerifyReport is the post-recovery invariant check (FR6, P3/P5).
type VerifyReport struct {
	Checks map[string]bool
}

func (r *VerifyReport) Pass() bool {
	if r == nil {
		return false
	}
	for _, ok := range r.Checks {
		if !ok {
			return false
		}
	}
	return true
}

// VerifyRecovery checks the recovery post-conditions against the
// pre-compromise state (FR6.2): P3 no resurrection (a revoked cert is never
// re-validated) and P5 minimal blast (nothing outside the invalidation set
// changed — including post-only additions; re-issued certs are allowed only
// for identities in the affected set).
func VerifyRecovery(pre, post *State, affectedCerts, affectedIdentities map[string]bool) *VerifyReport {
	r := &VerifyReport{Checks: map[string]bool{"P3": true, "P5": true}}
	for id, c := range pre.Certs {
		pc, ok := post.Certs[id]
		if c.Revoked && (!ok || !pc.Revoked || pc.Identity != c.Identity) {
			r.Checks["P3"] = false // resurrection
		}
		if !affectedCerts[id] && (!ok || pc != c) {
			r.Checks["P5"] = false // blast radius exceeded
		}
	}
	for id, pc := range post.Certs {
		if _, existed := pre.Certs[id]; existed {
			continue
		}
		if !affectedIdentities[pc.Identity] {
			r.Checks["P5"] = false // unplanned addition outside the re-issuance set
		}
	}
	return r
}
