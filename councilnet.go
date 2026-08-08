// councilnet: the networked council protocol (architecture §6.3, live).
// Council members run as persistent mTLS servers holding their FROST share
// and node key; the initiator (to-council recover --members ...) never sees
// member shares, members never sign anything they did not verify, and the
// root key NEVER exists anywhere. Two FROST rounds:
//
//	VOTE        initiator -> member: {bad_index, timeline}
//	            member verifies the chain prefix and replies VOTE_RESP with
//	            its FROST nonce commitment (round 1) iff the prefix is clean
//	            (honest members block bad evidence — P2's networked half)
//	COMMIT_REQ  initiator -> member: {frost: the handoff being signed,
//	            commitments: all members' nonce commitments, r, c, fork
//	            timeline, affected sets}
//	            member re-verifies the recovery post-conditions (P3/P5 — the
//	            ">=2 members re-executing" cross-check, now real), recomputes
//	            the FROST challenge from the transcript it actually sees,
//	            and replies COMMIT_RESP with its partial signature (round 2)
//
// The initiator verifies each partial signature against its commitment
// before aggregating into the handoff's Ed25519-compatible signature.
// ponytail: a member keeps ONE pending FROST session (nonces) at a time —
// recoveries are rare and serialized by epoch monotonicity; per-initiator
// sessions are the upgrade path if concurrency ever matters.

package trustorchestrator

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
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
	Checkpoint    []byte          `json:"checkpoint,omitempty"`
	NewPub        []byte          `json:"new_pub,omitempty"`
	Commit        []byte          `json:"commit,omitempty"`      // round 1: this member's D||E
	Commitments   map[string][]byte `json:"commitments,omitempty"` // round 2: all members' D||E
	R             []byte          `json:"r,omitempty"`           // round 2: aggregated nonce point
	C             []byte          `json:"c,omitempty"`           // round 2: challenge
	Frost         *FrostCommit    `json:"frost,omitempty"`       // round 2: handoff being signed
	Share         []byte          `json:"share,omitempty"`       // round 2: partial signature
	AffectedCerts []string        `json:"affected_certs,omitempty"`
	AffectedIDs   []string        `json:"affected_ids,omitempty"`
	Sig           []byte          `json:"sig,omitempty"`
	Error         string          `json:"error,omitempty"`
}

// CouncilMemberServer is one persistent council node: it answers VOTE and
// COMMIT_REQ over mTLS. The nonce commitment goes out only on a clean-prefix
// vote; the partial signature only after the recovery post-conditions
// re-verify AND the transcript challenge is recomputed locally.
type CouncilMemberServer struct {
	ID    string
	Share *FrostSigner
	key   ed25519.PrivateKey
	cfg   *tls.Config
	epochPath string // persistence: last committed epoch (gap 5)

	mu       sync.Mutex
	epoch    int64 // last committed epoch (persisted)
	pending  *pendingFrost // one in-flight FROST session
}

type pendingFrost struct {
	epoch      int64
	checkpoint []byte
	commit     []byte
}

// NewCouncilMemberServer creates a member node. epochPath persists the last
// committed epoch across restarts ("" = memory only). The wire identity is
// the share's participant ID (M1..Mn) — the FROST protocol indexes members
// by it; the mTLS cert identity (ServerName) is transport-only.
func NewCouncilMemberServer(id string, share *FrostSigner, key ed25519.PrivateKey, cfg *tls.Config, epochPath string) *CouncilMemberServer {
	if share != nil && share.ID != "" {
		id = share.ID
	}
	s := &CouncilMemberServer{ID: id, Share: share, key: key, cfg: cfg, epochPath: epochPath}
	if b, err := os.ReadFile(epochPath); err == nil {
		var f struct {
			Epoch int64 `json:"epoch"`
		}
		if json.Unmarshal(b, &f) == nil {
			s.epoch = f.Epoch
		}
	}
	return s
}

// persistEpoch writes the committed epoch to disk (best-effort).
func (s *CouncilMemberServer) persistEpoch() {
	if s.epochPath == "" {
		return
	}
	b, _ := json.Marshal(map[string]int64{"epoch": s.epoch})
	os.WriteFile(s.epochPath, b, 0o600)
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

// vote: reply with the nonce commitment (FROST round 1) iff the chain
// prefix up to bad_index verifies. A member never commits nonces to a
// recovery it does not believe in (P2).
func (s *CouncilMemberServer) vote(m CouncilMsg) CouncilMsg {
	resp := CouncilMsg{Kind: councilVoteResp, Node: s.ID, Error: "prefix failed verification"}
	tl, err := UnmarshalTimeline(m.Timeline)
	if err != nil {
		return resp
	}
	if m.BadIndex < 0 || !tl.VerifyPrefix(m.BadIndex) {
		return resp
	}
	if s.Share == nil {
		resp.Error = "no share loaded"
		return resp
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	epoch := lastEpoch(tl) + 1
	if epoch <= s.epoch {
		resp.Error = "stale epoch"
		return resp
	}
	if s.Share.used {
		resp.Error = "share already committed (single-use)"
		return resp
	}
	de, err := s.Share.Commit()
	if err != nil {
		resp.Error = "commit failed"
		return resp
	}
	s.pending = &pendingFrost{epoch: epoch, checkpoint: rollbackCheckpoint(tl, m.BadIndex), commit: de}
	resp.Vote = true
	resp.Commit = de
	resp.Epoch = epoch
	resp.Checkpoint = s.pending.checkpoint
	resp.Error = ""
	return resp
}

// commit: re-verify the recovery post-conditions (P3/P5) and the epoch
// contiguity, recompute the FROST challenge from the transcript, then send
// the partial signature (FROST round 2). The nonce pair from round 1 is
// single-use and cleared after signing.
func (s *CouncilMemberServer) commit(m CouncilMsg) CouncilMsg {
	resp := CouncilMsg{Kind: councilCommitOk, Node: s.ID, Error: "commit verification failed"}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || m.Frost == nil {
		resp.Error = "no pending session"
		return resp
	}
	if m.Epoch <= s.epoch || m.Prev != m.Epoch-1 {
		resp.Error = "epoch mismatch"
		return resp
	}
	// round-2 must bind round-1: same epoch and checkpoint the member voted for.
	if m.Frost.Epoch != s.pending.epoch || m.Frost.Checkpoint == nil ||
		!bytes.Equal(m.Frost.Checkpoint, s.pending.checkpoint) {
		resp.Error = "handoff does not match voted round"
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
	// recompute the challenge from what we actually saw; the aggregator
	// cannot slip a different transcript past us (round 2 binds round 1).
	ours := false
	for id, de := range m.Commitments {
		if id == s.Share.ID && bytes.Equal(de, s.pending.commit) {
			ours = true
		}
	}
	if !ours {
		resp.Error = "our commitment missing from transcript"
		return resp
	}
	trans := &FrostTranscript{M: m.Frost.descriptor(), Commits: m.Commitments, Xs: xsOf(m.Commitments)}
	r2, c2, err := ComputeChallenge(s.Share.GroupPub, trans.M, trans.Commits)
	if err != nil {
		resp.Error = "challenge recompute failed"
		return resp
	}
	if !bytes.Equal(r2, m.R) || !bytes.Equal(c2, m.C) {
		resp.Error = "transcript challenge mismatch"
		return resp
	}
	trans.R = r2
	trans.C = c2
	z, err := s.Share.SignShare(trans)
	if err != nil {
		resp.Error = "signing failed"
		return resp
	}
	s.epoch = m.Epoch
	s.persistEpoch()
	s.pending = nil // nonces are single-use
	resp.Share = z
	resp.Error = ""
	return resp
}

// xsOf maps every committed participant id to its canonical index.
func xsOf(commits map[string][]byte) map[string]int {
	xs := map[string]int{}
	for id := range commits {
		xs[id] = memberX(id)
	}
	return xs
}

// MemberEndpoint is one council node as seen by the initiator.
type MemberEndpoint struct {
	Addr       string            // host:port
	ServerName string            // member CN (certificate SAN/CN)
	Pub        ed25519.PublicKey // verified from the leaf cert at dial time
	PubShare   ed25519.PublicKey // the member's FROST pubkey share A_i (ceremony output, out-of-band)
}

// RemoteRecover is the networked recovery state machine: FROST round 1
// (votes + nonce commitments), recovery middle, FROST round 2 (partial
// signatures). Members that are down, refuse the vote, or fail the commit
// verification simply don't contribute — >= minVotes are required (P2).
// groupPub is the council's FROST group key (the recovery trust anchor),
// known out-of-band.
func RemoteRecover(tl *Timeline, evidence *TrustEvent, groupPub ed25519.PublicKey, endpoints []MemberEndpoint, cfg *tls.Config, minVotes int) (*RecoveryReport, error) {
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
	// ROUND 1: collect votes + nonce commitments.
	commits := map[string][]byte{}
	pubShares := map[string]ed25519.PublicKey{}
	xs := map[string]int{}
	for _, ep := range endpoints {
		if len(commits) >= minVotes {
			break
		}
		member, _, err := dialCouncil(ep, cfg)
		if err != nil {
			continue // unreachable member: no vote, no commitment (K3)
		}
		resp, err := roundTrip(member, CouncilMsg{Kind: councilVote, BadIndex: badIdx, Timeline: tlB})
		member.Close()
		if err != nil || !resp.Vote || len(resp.Commit) != 64 {
			continue // refused vote: honest member blocks bad evidence
		}
		commits[resp.Node] = resp.Commit
		xs[resp.Node] = memberX(resp.Node)
		pubShares[resp.Node] = ep.PubShare
	}
	if len(commits) < minVotes {
		return nil, errors.New("BLOCKED: fewer than minVotes members voted yes")
	}
	// The recovery middle produces the handoff to sign; members re-verify
	// the fork before their round-2 partial.
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	// the coordinator keeps the new epoch root; members never see it
	defer zeroize(seed)
	council := &Council{epoch: lastEpoch(tl)}
	fork, affected, identities, certDER, newPub, err := recoverRollback(tl, badIdx, seed, council.epoch, time.Now())
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	checkpoint := rollbackCheckpoint(tl, badIdx)
	fc := &FrostCommit{Epoch: lastEpoch(tl) + 1, Checkpoint: checkpoint, Prev: lastEpoch(tl), NewPub: newPub, Payload: certDER}
	forkB, _ := fork.Marshal(false)
	req := CouncilMsg{
		Kind: councilCommit, Epoch: fc.Epoch, Prev: fc.Prev,
		Checkpoint: checkpoint, NewPub: newPub, Payload: certDER,
		Frost: fc, Timeline: forkB, BadIndex: badIdx,
		AffectedCerts: keys(affected), AffectedIDs: keys(identities),
	}
	// ROUND 2: members re-verify P3/P5 and the transcript, then send
	// partial signatures. The challenge is derived only after all round-1
	// commitments are in (the aggregated nonce point needs them all).
	agg := NewFrostAggregator(groupPub, pubShares)
	agg.SetXs(xs)
	for id, de := range commits {
		if err := agg.AddCommit(id, de); err != nil {
			return nil, err
		}
	}
	r, cb, err := agg.Challenge(fc.descriptor())
	if err != nil {
		return nil, err
	}
	req.Commitments = commits
	req.R = r
	req.C = cb
	shares := map[string][]byte{}
	for _, ep := range endpoints {
		if len(shares) >= minVotes {
			break
		}
		member, _, err := dialCouncil(ep, cfg)
		if err != nil {
			continue
		}
		resp, err := roundTrip(member, req)
		member.Close()
		if err != nil || len(resp.Share) == 0 {
			fmt.Printf("DEBUG round2 %s: err=%v respErr=%q\n", ep.ServerName, err, resp.Error)
			continue // member rejected the fork: recovery is not verified
		}
		if err := agg.AddShare(resp.Node, resp.Share); err != nil {
			fmt.Printf("DEBUG addshare %s: %v\n", resp.Node, err)
			continue // bad partial signature: drop this member
		}
		shares[resp.Node] = resp.Share
	}
	if len(shares) < minVotes {
		return nil, errors.New("council: fewer than minVotes valid partial signatures")
	}
	sig, err := agg.Aggregate()
	if err != nil {
		return nil, err
	}
	fc.Sig = sig
	fc.Members = strSetKeys(shares)
	if !fc.Valid(groupPub, minVotes) {
		return nil, errors.New("council: aggregated signature invalid")
	}
	// Publish the canonical fork: handoff first (new-key events follow).
	fcJSON, _ := json.Marshal(fc)
	if _, err := fork.Append(EvRecovery, fcJSON, 0); err != nil {
		return nil, err
	}
	issued := reissueOnFork(fork, affected, identities, council.epoch)
	pre, _ := Rollback(tl, badIdx)
	r1 := VerifyRecovery(pre.Fold(), fork.Fold(), affected, identities)
	commitEv, _ := json.Marshal(map[string]any{
		"epoch": fc.Epoch, "checkpoint": fc.Checkpoint, "new_pub": fc.NewPub,
	})
	if _, err := fork.Append(EvCommit, commitEv, 0); err != nil {
		return nil, err
	}
	return &RecoveryReport{Commit: fc, Timeline: fork, Issued: issued, Verify: r1}, nil
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

// strSetKeys returns the keys of any string-keyed map (share sets, etc.).
func strSetKeys[T any](m map[string]T) []string {
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
