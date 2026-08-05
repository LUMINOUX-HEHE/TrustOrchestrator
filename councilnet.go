// councilnet: the networked council protocol (architecture §6.3, live).
// Council members run as persistent mTLS servers holding their shard and
// node key; the initiator (to-council recover --members ...) never sees
// member keys, members never see the root key. Two rounds:
//
//	VOTE        initiator -> member: {bad_index, timeline}
//	            member verifies the chain prefix; replies VOTE_RESP with its
//	            shard iff the prefix is clean (honest members block bad
//	            evidence — P2's networked half)
//	COMMIT_REQ  initiator -> member: {epoch, prev, root, payload, fork
//	            timeline, affected sets}; member re-verifies the recovery
//	            post-conditions (P3/P5 — the ">=2 members re-executing"
//	            cross-check, now real) and replies COMMIT_RESP with its
//	            signature over the epoch descriptor
//
// The initiator assembles the EpochCommit from >= minVotes member
// signatures and validates them against the members' verified leaf certs.
// ponytail: members keep the epoch counter in memory only — disk
// persistence when a deployment needs restart continuity. Reconstruction
// still happens on the initiator (the documented compromise point);
// threshold signing (no key assembly anywhere) is the future replacement.

package trustorchestrator

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	councilVote     = "VOTE"
	councilVoteResp = "VOTE_RESP"
	councilCommit   = "COMMIT_REQ"
	councilCommitOk = "COMMIT_RESP"
)

// CouncilMsg is one length-prefixed JSON frame of the council wire.
type CouncilMsg struct {
	Kind          string          `json:"kind"`
	Node          string          `json:"node"`
	Epoch         int64           `json:"epoch,omitempty"`
	Prev          int64           `json:"prev,omitempty"`
	Root          []byte          `json:"root,omitempty"`
	Payload       []byte          `json:"payload,omitempty"`
	BadIndex      int             `json:"bad_index,omitempty"`
	Timeline      json.RawMessage `json:"timeline,omitempty"`
	Vote          bool            `json:"vote,omitempty"`
	Shard         *Shard          `json:"shard,omitempty"`
	AffectedCerts []string        `json:"affected_certs,omitempty"`
	AffectedIDs   []string        `json:"affected_ids,omitempty"`
	Sig           []byte          `json:"sig,omitempty"`
	Error         string          `json:"error,omitempty"`
}

// CouncilMemberServer is one persistent council node: it answers VOTE and
// COMMIT_REQ over mTLS. The shard is sent only on a clean-prefix vote; the
// commit signature only after the recovery post-conditions re-verify.
type CouncilMemberServer struct {
	ID    string
	Shard *Shard
	key   ed25519.PrivateKey
	cfg   *tls.Config

	mu    sync.Mutex
	epoch int64 // last committed epoch seen (in-memory)
}

func NewCouncilMemberServer(id string, shard *Shard, key ed25519.PrivateKey, cfg *tls.Config) *CouncilMemberServer {
	return &CouncilMemberServer{ID: id, Shard: shard, key: key, cfg: cfg}
}

// Serve runs the accept loop until the listener fails or connErr stops it.
func (s *CouncilMemberServer) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// handle serves one member connection (VOTE then COMMIT_REQ in order).
func (s *CouncilMemberServer) handle(conn net.Conn) error {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n > 1<<20 {
			return errors.New("councilnet: frame too large")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		var m CouncilMsg
		if err := json.Unmarshal(buf, &m); err != nil {
			return err
		}
		resp, err := s.dispatch(m)
		if err != nil {
			return err
		}
		if err := writeCouncilFrame(conn, resp); err != nil {
			return err
		}
	}
}

func (s *CouncilMemberServer) dispatch(m CouncilMsg) (CouncilMsg, error) {
	switch m.Kind {
	case councilVote:
		return s.vote(m), nil
	case councilCommit:
		return s.commit(m), nil
	}
	return CouncilMsg{}, fmt.Errorf("councilnet: unknown kind %q", m.Kind)
}

// vote: reply with the shard iff the chain prefix up to bad_index verifies.
// A member never sends its shard to a recovery it does not believe in (P2).
func (s *CouncilMemberServer) vote(m CouncilMsg) CouncilMsg {
	resp := CouncilMsg{Kind: councilVoteResp, Node: s.ID, Error: "prefix failed verification"}
	tl, err := UnmarshalTimeline(m.Timeline)
	if err != nil {
		return resp
	}
	if m.BadIndex < 0 || !tl.VerifyPrefix(m.BadIndex) {
		return resp
	}
	resp.Vote = true
	resp.Shard = s.Shard
	resp.Error = ""
	return resp
}

// commit: re-verify the recovery post-conditions (P3/P5) and the epoch
// contiguity, then sign the descriptor with the member's node key. Epoch
// advances monotonically; the member starts at 0 in memory, so an
// initiator whose timeline already carries COMMITs still gets signatures.
func (s *CouncilMemberServer) commit(m CouncilMsg) CouncilMsg {
	resp := CouncilMsg{Kind: councilCommitOk, Node: s.ID, Error: "commit verification failed"}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.Epoch <= s.epoch || m.Prev != m.Epoch-1 {
		resp.Error = "epoch mismatch"
		return resp
	}
	fork, err := UnmarshalTimeline(m.Timeline)
	if err != nil {
		return resp
	}
	if !fork.Verify() {
		return resp
	}
	pre := prefixState(fork, m.BadIndex)
	post := fork.Fold()
	if !VerifyRecovery(pre, post, strSet(m.AffectedCerts), strSet(m.AffectedIDs)).Pass() {
		return resp
	}
	resp.Sig = ed25519.Sign(s.key, epochDescriptor(m.Epoch, m.Root, m.Prev, m.Payload))
	s.epoch = m.Epoch
	resp.Error = ""
	return resp
}

// MemberEndpoint is one council node as seen by the initiator.
type MemberEndpoint struct {
	Addr       string // host:port
	ServerName string // member CN (certificate SAN/CN)
	Pub        ed25519.PublicKey // verified from the leaf cert at dial time
}

// RemoteRecover is the networked recovery state machine: vote round,
// reconstruction (initiator-side, zeroized), recovery middle, commit round.
// Members that are down, refuse the vote, or fail the commit verification
// simply don't contribute — >= minVotes are required (P2).
func RemoteRecover(tl *Timeline, evidence *TrustEvent, endpoints []MemberEndpoint, cfg *tls.Config, minVotes int) (*RecoveryReport, error) {
	badIdx, err := evidenceBadIndex(evidence)
	if err != nil {
		return nil, err
	}
	if !tl.VerifyPrefix(badIdx) {
		return nil, errors.New("council: prefix failed verification")
	}
	tlB, err := tl.Marshal(false) // members never see the signing key
	if err != nil {
		return nil, err
	}
	// ROUND 1: collect votes + shards.
	var shards []*Shard
	pubs := map[string]ed25519.PublicKey{}
	for _, ep := range endpoints {
		if len(shards) >= minVotes {
			break
		}
		member, pub, err := dialCouncil(ep, cfg)
		if err != nil {
			continue // unreachable member: no vote, no shard (K3)
		}
		pubs[ep.ServerName] = pub
		resp, err := roundTrip(member, CouncilMsg{Kind: councilVote, BadIndex: badIdx, Timeline: tlB})
		member.Close()
		if err != nil || !resp.Vote || resp.Shard == nil {
			continue // refused vote: honest member blocks bad evidence
		}
		shards = append(shards, resp.Shard)
	}
	if len(shards) < minVotes {
		return nil, errors.New("BLOCKED: fewer than minVotes members voted yes")
	}
	// RECONSTRUCT (initiator-side, zeroized after use) + recovery middle.
	root, err := ShamirJoin(shards)
	if err != nil {
		return nil, fmt.Errorf("council: reconstruction failed: %w", err)
	}
	defer zeroize(root)
	fork, affected, identities, interCert, issued, err := recoverFork(tl, badIdx, root, lastEpoch(tl))
	if err != nil {
		return nil, err
	}
	// ROUND 2: members re-verify P3/P5 and sign the commit descriptor.
	epoch := lastEpoch(tl) + 1
	forkB, _ := fork.Marshal(false)
	req := CouncilMsg{
		Kind: councilCommit, Epoch: epoch, Prev: epoch - 1,
		Root: fork.Head(), Payload: interCert, Timeline: forkB,
		BadIndex: badIdx,
		AffectedCerts: keys(affected), AffectedIDs: keys(identities),
	}
	sigs := map[string][]byte{}
	for _, ep := range endpoints {
		if len(sigs) >= minVotes {
			break
		}
		member, _, err := dialCouncil(ep, cfg)
		if err != nil {
			continue
		}
		resp, err := roundTrip(member, req)
		member.Close()
		if err != nil || len(resp.Sig) == 0 {
			continue // member rejected the fork: recovery is not verified
		}
		sigs[ep.ServerName] = resp.Sig
	}
	commit := &EpochCommit{Epoch: epoch, RootHash: fork.Head(), Prev: epoch - 1,
		Payload: interCert, Sigs: sigs}
	if !commit.Valid(pubs, minVotes) {
		return nil, errors.New("council: fewer than minVotes valid commit signatures")
	}
	// VERIFY: local post-condition check, then publish the canonical fork.
	pre, _ := Rollback(tl, badIdx)
	r := VerifyRecovery(pre.Fold(), fork.Fold(), affected, identities)
	commitEv, _ := json.Marshal(map[string]any{"epoch": commit.Epoch, "root": fork.Head()})
	fork.Append(EvCommit, commitEv, 0)
	return &RecoveryReport{Commit: commit, Timeline: fork, Issued: issued, Verify: r}, nil
}

// lastEpoch is the highest committed epoch on the timeline.
func lastEpoch(tl *Timeline) int64 {
	var e int64
	for _, ev := range tl.Events() {
		if ev.Type != EvCommit {
			continue
		}
		var p struct {
			Epoch int64 `json:"epoch"`
		}
		if json.Unmarshal(ev.Payload, &p) == nil && p.Epoch > e {
			e = p.Epoch
		}
	}
	return e
}

// prefixState folds the verified prefix of a recovered timeline — the
// pre-compromise state a member re-checks against.
func prefixState(tl *Timeline, badIdx int) *State {
	if badIdx <= 0 {
		return &State{Certs: map[string]Cert{}}
	}
	pre, err := tl.Fork(tl.Events()[badIdx-1].Hash())
	if err != nil {
		return &State{Certs: map[string]Cert{}}
	}
	return pre.Fold()
}

func strSet(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// dialCouncil opens the mTLS connection and verifies the peer's leaf cert
// (CN must match the endpoint) — the member's identity on the wire.
func dialCouncil(ep MemberEndpoint, cfg *tls.Config) (net.Conn, ed25519.PublicKey, error) {
	cfg.ServerName = ep.ServerName
	conn, err := tls.Dial("tcp", ep.Addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		conn.Close()
		return nil, nil, errors.New("councilnet: no peer certificate")
	}
	peer := state.PeerCertificates[0]
	if err := VerifyPeerIdentity(peer, ep.ServerName); err != nil {
		conn.Close()
		return nil, nil, err
	}
	pub, ok := peer.PublicKey.(ed25519.PublicKey)
	if !ok {
		conn.Close()
		return nil, nil, errors.New("councilnet: peer key is not ed25519")
	}
	return conn, pub, nil
}

// roundTrip sends one frame and reads one response frame.
func roundTrip(conn net.Conn, m CouncilMsg) (CouncilMsg, error) {
	if err := writeCouncilFrame(conn, m); err != nil {
		return CouncilMsg{}, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return CouncilMsg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 1<<20 {
		return CouncilMsg{}, errors.New("councilnet: frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return CouncilMsg{}, err
	}
	var resp CouncilMsg
	if err := json.Unmarshal(buf, &resp); err != nil {
		return CouncilMsg{}, err
	}
	return resp, nil
}

func writeCouncilFrame(conn net.Conn, m CouncilMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}
