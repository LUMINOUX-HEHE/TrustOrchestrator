// Trust Orchestrator core: the trust timeline (T1 root).
package trustorchestrator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
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
	EvKeyRotate     = "KEY_ROTATE"
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
	mu     sync.Mutex
	events []TrustEvent
	key    ed25519.PrivateKey // nil for read-only (loaded) timelines
	pub    ed25519.PublicKey  // current verification key (rotates via EvKeyRotate)
	start  ed25519.PublicKey  // key that signed event[0]; nil = pub (never rotated)
	// councilPub is the council's FROST group key — the recovery trust
	// anchor that authorizes EvRecovery key handoffs. nil for timelines
	// without council-authorized recovery.
	councilPub ed25519.PublicKey
	// private keys rotated away (one per recovery), so forks can continue
	// under the key that was current at their branch point
	rotations []rotKey
}

type rotKey struct {
	at  int // index of the EvKeyRotate event
	key ed25519.PrivateKey
}

func NewTimeline(key ed25519.PrivateKey) *Timeline {
	pub := key.Public().(ed25519.PublicKey)
	return &Timeline{key: key, pub: pub, start: pub}
}

// Pub returns the current verification key (public).
func (t *Timeline) Pub() ed25519.PublicKey {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.pub...)
}

// Head returns the hash of the last event, or nil for an empty chain.
func (t *Timeline) Head() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.head()
}

func (t *Timeline) head() []byte {
	if len(t.events) == 0 {
		return nil
	}
	return t.events[len(t.events)-1].Hash()
}

// Events exposes the chain for read-only consumers (auditors, operators).
func (t *Timeline) Events() []TrustEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]TrustEvent, len(t.events))
	copy(cp, t.events)
	return cp
}

// Append signs and chains a new event onto the current head (FR1.1, FR1.3).
func (t *Timeline) Append(typ string, payload []byte, ts int64) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.append(typ, payload, ts)
}

func (t *Timeline) append(typ string, payload []byte, ts int64) ([]byte, error) {
	if t.key == nil {
		return nil, fmt.Errorf("timeline: read-only (loaded from file)")
	}
	e := TrustEvent{Type: typ, Timestamp: ts, Payload: payload, ParentHash: t.head()}
	e.Signature = ed25519.Sign(t.key, e.canonical())
	t.events = append(t.events, e)
	return e.Hash(), nil
}

// SetCouncilPub binds the council FROST group key to the timeline, the
// trust anchor that EvRecovery handoffs are verified against.
func (t *Timeline) SetCouncilPub(pub ed25519.PublicKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.councilPub = append([]byte(nil), pub...)
}

// CouncilPub returns the council trust anchor, or nil if unset.
func (t *Timeline) CouncilPub() ed25519.PublicKey {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.councilPub...)
}

// FrostCommit is the payload of an EvRecovery event: the council's
// threshold-signed handoff that switches the chain to a new epoch root key.
// walkVerify trusts the new key only if the embedded FrostCommit verifies
// against the timeline's councilPub and binds to this exact chain position.
type FrostCommit struct {
	Epoch      int64    `json:"epoch"`
	Checkpoint []byte   `json:"checkpoint"` // head of the verified prefix (nil for genesis recovery)
	Prev       int64    `json:"prev"`
	NewPub     []byte   `json:"new_pub"` // new epoch root verification key (32 bytes)
	Payload    []byte   `json:"payload"` // e.g. new root CA cert DER
	Sig        []byte   `json:"sig"`     // aggregated FROST signature over the above
	Members    []string `json:"members"` // signer ids (audit)
}

// descriptor is the exact bytes the council threshold-signs.
func (p *FrostCommit) descriptor() []byte {
	b, _ := json.Marshal(struct {
		Epoch      int64  `json:"epoch"`
		Checkpoint []byte `json:"checkpoint"`
		Prev       int64  `json:"prev"`
		NewPub     []byte `json:"new_pub"`
		Payload    []byte `json:"payload"`
	}{p.Epoch, p.Checkpoint, p.Prev, p.NewPub, p.Payload})
	return b
}

// Valid accepts the handoff iff >= min distinct members signed it: the
// aggregated FROST signature is a standard Ed25519 signature over the
// descriptor, so one Verify call against the group key suffices.
func (p *FrostCommit) Valid(groupPub ed25519.PublicKey, min int) bool {
	if len(p.Members) < min || len(p.NewPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(groupPub, p.descriptor(), p.Sig)
}

// keyRotatePayload is the EvKeyRotate event payload: the new verification
// key, bound into the chain by the OLD key's signature.
type keyRotatePayload struct {
	Pub []byte `json:"pub"`
}

// RotateKey transitions the timeline to a new signing key. The transition
// itself is a chain event signed by the current key, so verifiers switch
// keys exactly where the chain says so (a fork after recovery/re-key
// verifies its full length, old prefix under the old key, new suffix under
// the new one).
func (t *Timeline) RotateKey(newKey ed25519.PrivateKey, ts int64) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.key == nil {
		return nil, fmt.Errorf("timeline: read-only (loaded from file)")
	}
	p, err := json.Marshal(keyRotatePayload{Pub: newKey.Public().(ed25519.PublicKey)})
	if err != nil {
		return nil, err
	}
	h, err := t.append(EvKeyRotate, p, ts)
	if err != nil {
		return nil, err
	}
	t.rotations = append(t.rotations, rotKey{at: len(t.events) - 1, key: t.key})
	t.key = newKey
	t.pub = newKey.Public().(ed25519.PublicKey)
	return h, nil
}

// walkVerify checks events[0..n): hashes, parent links, and signatures,
// following KEY_ROTATE events (signed by the outgoing key) and EV_RECOVERY
// events (FROST-authorized handoff) to switch the verification key
// mid-chain. Returns the first bad index, or -1. A rotation event that
// can't be parsed is treated as a chain break (it was signed by the old
// key, so a malformed rotation is deliberate).
func walkVerify(events []TrustEvent, startPub ed25519.PublicKey, councilPub ed25519.PublicKey, n int) int {
	pub := startPub
	for i := 0; i < n; i++ {
		e := events[i]
		if i == 0 && e.ParentHash != nil {
			return i
		}
		if i > 0 && !bytes.Equal(e.ParentHash, events[i-1].Hash()) {
			return i
		}
		if e.Type == EvRecovery {
			if len(councilPub) != ed25519.PublicKeySize {
				return i // no trust anchor: recovery handoffs are rejected
			}
			var fc FrostCommit
			if json.Unmarshal(e.Payload, &fc) != nil || !fc.Valid(councilPub, 1) {
				return i
			}
			// the handoff must reference the exact chain head before it
			var want []byte
			if i > 0 {
				want = events[i-1].Hash()
			}
			if !bytes.Equal(fc.Checkpoint, want) {
				return i
			}
			pub = fc.NewPub
		}
		if !ed25519.Verify(pub, e.canonical(), e.Signature) {
			return i
		}
		if e.Type == EvKeyRotate {
			var p keyRotatePayload
			if json.Unmarshal(e.Payload, &p) != nil || len(p.Pub) != ed25519.PublicKeySize {
				return i
			}
			pub = ed25519.PublicKey(p.Pub)
		}
	}
	return -1
}

// Verify re-hashes the chain and re-checks every signature (FR1.2).
func (t *Timeline) Verify() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.locateBadEvent() == -1
}

// VerifyPrefix verifies only events[0..n-1] (FR1.2). Recovery verifies the
// good prefix — the tampered region beyond it is exactly what recovery
// rolls back from.
func (t *Timeline) VerifyPrefix(n int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n > len(t.events) {
		n = len(t.events)
	}
	return walkVerify(t.events, t.startPub(), t.councilPub, n) == -1
}

// LocateBadEvent returns the index of the first event that breaks the chain
// (parent mismatch or bad signature), or -1 (W2 detector core, §6.1).
func (t *Timeline) LocateBadEvent() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.locateBadEvent()
}

func (t *Timeline) locateBadEvent() int {
	return walkVerify(t.events, t.startPub(), t.councilPub, len(t.events))
}

// pubForPrefix returns the verification key current after events[0..idx]
// (the start key is replaced by any rotations/recoveries in the prefix;
// the prefix is verified before Fork, so parsing the handoff is enough).
func pubForPrefix(events []TrustEvent, startPub ed25519.PublicKey, idx int) ed25519.PublicKey {
	pub := startPub
	for i := 0; i <= idx; i++ {
		e := events[i]
		switch e.Type {
		case EvKeyRotate:
			var p keyRotatePayload
			if json.Unmarshal(e.Payload, &p) == nil && len(p.Pub) == ed25519.PublicKeySize {
				pub = ed25519.PublicKey(p.Pub)
			}
		case EvRecovery:
			var fc FrostCommit
			if json.Unmarshal(e.Payload, &fc) == nil && len(fc.NewPub) == ed25519.PublicKeySize {
				pub = ed25519.PublicKey(fc.NewPub)
			}
		}
	}
	return pub
}

// Fork branches at the verified checkpoint hash. The original chain is
// preserved by the caller as evidence (architecture §5.1); replay of the
// trusted prefix is implicit in the copy.
func (t *Timeline) Fork(atHash []byte) (*Timeline, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx := -1
	for i := range t.events {
		if bytes.Equal(t.events[i].Hash(), atHash) {
			idx = i
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("checkpoint %x not in timeline", atHash)
	}
	f := &Timeline{key: t.keyAt(idx), start: pubForPrefix(t.events, t.startPub(), idx),
		councilPub: t.councilPub}
	f.pub = f.start
	f.events = append(f.events, t.events[:idx+1]...)
	return f, nil
}

// keyAt is the signing key current at event idx (nil when unknown): the
// first rotation at-or-after idx holds the key signed up to and including
// that rotation event; past the last rotation, the live key applies.
func (t *Timeline) keyAt(idx int) ed25519.PrivateKey {
	for _, r := range t.rotations {
		if r.at >= idx {
			return r.key
		}
	}
	return t.key
}

// startPub is the verification key that signed event[0].
func (t *Timeline) startPub() ed25519.PublicKey {
	if t.start != nil {
		return t.start
	}
	return t.pub
}

// State is the derived trust state; fold is a pure, deterministic re-fold
// (FR1.4, L1-L3).
type State struct {
	Certs map[string]Cert
}

// timelineFile is the on-disk form of a timeline (operator handoff,
// auditor mirror dumps, recovery evidence).
type timelineFile struct {
	Events     []TrustEvent       `json:"events"`
	Pub        ed25519.PublicKey  `json:"public_key"`
	StartPub   ed25519.PublicKey  `json:"start_pub,omitempty"` // key at event[0]; missing = Pub
	CouncilPub ed25519.PublicKey  `json:"council_pub,omitempty"`
	Key        ed25519.PrivateKey `json:"key,omitempty"` // demo/evidence only; production dumps omit it
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
	t.mu.Lock()
	defer t.mu.Unlock()
	f := timelineFile{Events: t.events, Pub: t.pub}
	if t.start != nil {
		f.StartPub = t.start
	}
	if t.councilPub != nil {
		f.CouncilPub = t.councilPub
	}
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

// UnmarshalTimeline parses a timeline from its JSON form. The keys are
// validated at parse time: ed25519.Verify/Sign panic on wrong-length keys,
// and a crafted file must fail cleanly, not crash the verifier.
func UnmarshalTimeline(b []byte) (*Timeline, error) {
	var f timelineFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if len(f.Pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("timeline: bad public key length %d", len(f.Pub))
	}
	if len(f.StartPub) != 0 && len(f.StartPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("timeline: bad start public key length %d", len(f.StartPub))
	}
	if len(f.Key) != 0 && len(f.Key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("timeline: bad private key length %d", len(f.Key))
	}
	if len(f.CouncilPub) != 0 && len(f.CouncilPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("timeline: bad council pub length %d", len(f.CouncilPub))
	}
	var start ed25519.PublicKey
	if len(f.StartPub) == ed25519.PublicKeySize {
		start = f.StartPub
	} else {
		start = f.Pub
	}
	var council ed25519.PublicKey
	if len(f.CouncilPub) == ed25519.PublicKeySize {
		council = f.CouncilPub
	}
	return &Timeline{events: f.Events, pub: f.Pub, start: start, councilPub: council, key: f.Key}, nil
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
	t.mu.Lock()
	defer t.mu.Unlock()
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
