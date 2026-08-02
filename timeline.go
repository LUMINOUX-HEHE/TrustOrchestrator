// Trust Orchestrator core: the trust timeline (T1 root).
package trustorchestrator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

// Event types (wire contract, architecture report §5.1).
const (
	EvKeyGen        = "KEY_GEN"
	EvIssue         = "ISSUE"
	EvRevoke        = "REVOKE"
	EvPolicyChange  = "POLICY_CHANGE"
	EvRecovery      = "RECOVERY"
	EvCommit        = "COMMIT"
	EvShardActivity = "SHARD_ACTIVITY"
	EvDetected      = "DETECTED"
)

// TrustEvent is one signed, chained state transition (SRS FR1.1).
type TrustEvent struct {
	Type       string
	Timestamp  int64
	Payload    []byte
	ParentHash []byte
	Signature  []byte
}

// canonical is the signed bytes: the event with the signature blanked.
func (e TrustEvent) canonical() []byte {
	c := e
	c.Signature = nil
	b, _ := json.Marshal(c)
	return b
}

// Hash is the chaining hash of the event.
func (e TrustEvent) Hash() []byte {
	h := sha256.Sum256(append(e.canonical(), e.Signature...))
	return h[:]
}

// Timeline is the immutable, forkable hash chain of trust events.
// ponytail: linear hash chain, not a binary Merkle tree — inclusion proofs
// are needed only when auditor logs exist; add the tree then.
type Timeline struct {
	events []TrustEvent
	key    ed25519.PrivateKey // nil for read-only (loaded) timelines
	pub    ed25519.PublicKey  // verification key; equals key.Public() when key != nil
}

func NewTimeline(key ed25519.PrivateKey) *Timeline {
	return &Timeline{key: key, pub: key.Public().(ed25519.PublicKey)}
}

// Head returns the hash of the last event, or nil for an empty chain.
func (t *Timeline) Head() []byte {
	if len(t.events) == 0 {
		return nil
	}
	return t.events[len(t.events)-1].Hash()
}

// Events exposes the chain for read-only consumers (auditors, operators).
func (t *Timeline) Events() []TrustEvent { return t.events }

// Append signs and chains a new event onto the current head (FR1.1, FR1.3).
func (t *Timeline) Append(typ string, payload []byte, ts int64) ([]byte, error) {
	if t.key == nil {
		return nil, fmt.Errorf("timeline: read-only (loaded from file)")
	}
	e := TrustEvent{Type: typ, Timestamp: ts, Payload: payload, ParentHash: t.Head()}
	e.Signature = ed25519.Sign(t.key, e.canonical())
	t.events = append(t.events, e)
	return e.Hash(), nil
}

// Verify re-hashes the chain and re-checks every signature (FR1.2).
func (t *Timeline) Verify() bool {
	return t.LocateBadEvent() == -1
}

// VerifyPrefix verifies only events[0..n-1] (FR1.2). Recovery verifies the
// good prefix — the tampered region beyond it is exactly what recovery
// rolls back from.
func (t *Timeline) VerifyPrefix(n int) bool {
	if n > len(t.events) {
		n = len(t.events)
	}
	for i := 0; i < n; i++ {
		e := t.events[i]
		if i == 0 && e.ParentHash != nil {
			return false
		}
		if i > 0 && !bytes.Equal(e.ParentHash, t.events[i-1].Hash()) {
			return false
		}
		if !ed25519.Verify(t.pub, e.canonical(), e.Signature) {
			return false
		}
	}
	return true
}

// LocateBadEvent returns the index of the first event that breaks the chain
// (parent mismatch or bad signature), or -1 (W2 detector core, §6.1).
func (t *Timeline) LocateBadEvent() int {
	for i, e := range t.events {
		if i == 0 && e.ParentHash != nil {
			return i
		}
		if i > 0 && !bytes.Equal(e.ParentHash, t.events[i-1].Hash()) {
			return i
		}
		if !ed25519.Verify(t.pub, e.canonical(), e.Signature) {
			return i
		}
	}
	return -1
}

// Fork branches at the verified checkpoint hash. The original chain is
// preserved by the caller as evidence (architecture §5.1); replay of the
// trusted prefix is implicit in the copy.
func (t *Timeline) Fork(atHash []byte) (*Timeline, error) {
	idx := -1
	for i := range t.events {
		if bytes.Equal(t.events[i].Hash(), atHash) {
			idx = i
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("checkpoint %x not in timeline", atHash)
	}
	f := &Timeline{key: t.key, pub: t.pub}
	f.events = append(f.events, t.events[:idx+1]...)
	return f, nil
}

// State is the derived trust state; fold is a pure, deterministic re-fold
// (FR1.4, L1-L3).
type State struct {
	Certs map[string]Cert
}

// timelineFile is the on-disk form of a timeline (operator handoff,
// auditor mirror dumps, recovery evidence).
type timelineFile struct {
	Events []TrustEvent       `json:"events"`
	Pub    ed25519.PublicKey  `json:"public_key"`
	Key    ed25519.PrivateKey `json:"key,omitempty"` // demo/evidence only; production dumps omit it
}

// Save persists the timeline (events + verification key). The signing key
// is included for evidence dumps produced by the benchmark so the council
// CLI can replay the exact recovery; production tooling omits it.
func (t *Timeline) Save(path string, includeKey bool) error {
	b, err := t.Marshal(includeKey)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// MarshalTimeline is the JSON form used by Save and by evidence files.
func (t *Timeline) Marshal(includeKey bool) ([]byte, error) {
	f := timelineFile{Events: t.events, Pub: t.pub}
	if includeKey && t.key != nil {
		f.Key = t.key
	}
	return json.Marshal(f)
}

// LoadTimeline restores a timeline from a Save dump.
func LoadTimeline(path string) (*Timeline, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return UnmarshalTimeline(b)
}

// UnmarshalTimeline parses a timeline from its JSON form.
func UnmarshalTimeline(b []byte) (*Timeline, error) {
	var f timelineFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &Timeline{events: f.Events, pub: f.Pub, key: f.Key}, nil
}

type Cert struct {
	Identity string
	Revoked  bool
}

type issuePayload struct {
	CertID   string `json:"cert_id"`
	Identity string `json:"identity"`
	Via      string `json:"via,omitempty"`
}

// Fold derives the trust state from the event prefix. Rollback is just a
// fold of a shorter prefix — nothing else (architecture §6.5).
func (t *Timeline) Fold() *State {
	s := &State{Certs: map[string]Cert{}}
	for _, e := range t.events {
		switch e.Type {
		case EvIssue:
			var p issuePayload
			if json.Unmarshal(e.Payload, &p) != nil {
				continue // malformed payload: verifier's problem, fold stays deterministic
			}
			if c, ok := s.Certs[p.CertID]; ok && c.Revoked {
				continue // L3: revoked is sticky, rollback never re-validates it
			}
			s.Certs[p.CertID] = Cert{Identity: p.Identity}
		case EvRevoke:
			var p struct {
				CertID string `json:"cert_id"`
			}
			if json.Unmarshal(e.Payload, &p) != nil {
				continue
			}
			if c, ok := s.Certs[p.CertID]; ok {
				c.Revoked = true
				s.Certs[p.CertID] = c
			}
		}
	}
	return s
}
