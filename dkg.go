package trustorchestrator

// dkg.go — interactive distrustful DKG over the council wire: the upgrade
// from DkgCeremony's trusted ceremony box. Five members, each on its own
// machine, jointly generate the FROST group key; no single actor — there
// is no coordinator — ever holds more than its own polynomial and share.
// Wire shape follows the FROST DKG protocol (draft-irtf-cfrg-frost):
// public commitment vectors exchanged pairwise, the secret polynomial
// evaluation delivered over the same mTLS channel (PQ-sealed), every share
// verified against the sender's Feldman commitments before it is accepted.
//
// Topology: each member listens on its own address and dials the peers
// with HIGHER ids (M1 dials M2..M5, M2 dials M3..M5, ...): one connection
// per pair, no deadlock, no coordinator. A session id binds all messages
// to one ceremony (derived from the sorted id|addr list, so every member
// derives the same value).
//
// Round structure (one frame per pair, PQ-sealed after the mTLS handshake):
//
//	dialer -> peer:  DKG_EXCHANGE {commits of dialer, f_dialer(peer)}
//	peer   -> dialer: DKG_EXCHANGE {commits of peer,   f_peer(dialer)}
//
// both sides verify the received share against the sender's commitments;
// a member with a bad share aborts. Finalize = DkgFinalize over the own
// material plus every verified received piece: each member ends with its
// own FrostSigner — the input tensor is the union of every member's
// polynomial, and no single machine holds more than one row of it.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"
)

// DkgNode is one side of a pairwise DKG ceremony: it generates its own
// polynomial, exchanges commitments and shares with every other member
// over authenticated connections, and finalizes into its own FROST share.
type DkgNode struct {
	ID    string
	N, T  int
	addr  string
	cfg   *tls.Config
	peers map[string]string // id -> address (all members, self included)

	session []byte // ceremony binding, derived from the sorted id|addr list
	mat     *DkgMaterial
	ownHex  []string // this member's commitments, hex

	mu          sync.Mutex
	peerCommits map[string][]string
	received    map[string]*big.Int // peer id -> f_peer(my index)
	done        int                 // completed pairs
	signer      *FrostSigner
}

// NewDkgNode prepares one ceremony participant. peers must map every
// member id (self included) to its dial address; cfg is the member's mTLS
// identity (verified against the CA). The ceremony has no coordinator: the
// session id binds all pairwise exchanges to this ceremony, and a replayed
// exchange from an older one is rejected.
func NewDkgNode(id, addr string, n, t int, cfg *tls.Config, peers map[string]string) (*DkgNode, error) {
	if t < 2 || t > n || len(peers) != n {
		return nil, errors.New("dkg: need 2 <= threshold <= members")
	}
	if _, ok := peers[id]; !ok {
		return nil, errors.New("dkg: own id missing from peers")
	}
	seen := map[int]bool{}
	for pid := range peers {
		x := memberX(pid)
		if x < 1 || x > n || seen[x] {
			return nil, fmt.Errorf("dkg: member ids must be distinct M1..M%d", n)
		}
		seen[x] = true
	}
	if addr == "" {
		addr = peers[id]
	}
	mat, err := DkgGenerate(id, n, t)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(peers))
	for k := range peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k + "|" + peers[k]))
		h.Write([]byte{0})
	}
	ownHex := make([]string, len(mat.Commits))
	for i, p := range mat.Commits {
		ownHex[i] = hex.EncodeToString(encode(p))
	}
	return &DkgNode{
		ID: id, N: n, T: t, addr: addr, cfg: cfg, peers: peers,
		session: h.Sum(nil), mat: mat, ownHex: ownHex,
		peerCommits: map[string][]string{}, received: map[string]*big.Int{},
	}, nil
}

// Run executes the ceremony: listen for the lower-id peers, dial and
// exchange with the higher-id peers, then finalize once all N-1 pairs are
// done. Returns the group public key (must be identical on every member).
// ponytail: completion is polled (10ms); a ceremony is a rare one-shot
// event on a handful of machines — a condition broadcast would be the
// upgrade if thousands of members ever join.
func (d *DkgNode) Run() (ed25519.PublicKey, error) {
	ln, err := tls.Listen("tcp", d.addr, d.cfg)
	if err != nil {
		return nil, err
	}
	return d.RunOn(ln)
}

// RunOn is Run over an already-bound listener (tests reserve ports first).
func (d *DkgNode) RunOn(ln net.Listener) (ed25519.PublicKey, error) {
	defer ln.Close()
	errc := make(chan error, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			go d.servePeer(conn, errc)
		}
	}()
	ids := make([]string, 0, len(d.peers))
	for id := range d.peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, pid := range ids {
		if memberX(pid) > memberX(d.ID) { // lower id dials: one conn per pair
			// ponytail: dial retried 15s for members that boot late;
			// post-dial errors (Feldman/record) fail fast on purpose.
			if err := d.dialWithRetry(pid, 30*500*time.Millisecond); err != nil {
				return nil, err
			}
		}
	}
	for {
		if d.count() >= d.N-1 {
			break
		}
		select {
		case err := <-errc:
			if err != nil {
				return nil, err
			}
		case <-time.After(10 * time.Millisecond):
		}
	}
	return d.finish()
}

// Signer returns the member's finalized FROST share (valid after Run).
func (d *DkgNode) Signer() *FrostSigner {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signer
}

// count reports the number of completed pairwise exchanges.
func (d *DkgNode) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.done
}

// exchange dials one higher-id peer over mTLS (PQ handshake), sends this
// member's commitments and share evaluation for that peer, and verifies
// the peer's reply before recording it. Shares never transit any third
// party: the only hops are the two endpoints.
func (d *DkgNode) exchange(pid string) error {
	conn, _, err := dialCouncil(MemberEndpoint{Addr: d.peers[pid], ServerName: pid}, d.cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := roundTripPQ(conn, CouncilMsg{
		Kind: dkgExchange, Session: d.session, From: d.ID,
		Commits: d.ownHex, ShareVal: scalarBytes(d.mat.Shares[pid]),
	})
	if err != nil {
		return err
	}
	if resp.Kind != dkgExchange || !bytes.Equal(resp.Session, d.session) || resp.From != pid {
		return errors.New("dkg: bad exchange reply from " + pid)
	}
	return d.recordPeer(pid, resp.Commits, resp.ShareVal)
}

// dialWithRetry: the dialer side of the pair exchange, retrying connect
// failures until the peer's listener is up; everything after the dial is
// fail-fast (a malformed share is a bad ceremony, not a retry).
func (d *DkgNode) dialWithRetry(pid string, window time.Duration) error {
	deadline := time.Now().Add(window)
	for {
		err := d.exchange(pid)
		if err == nil {
			return nil
		}
		var ne *net.OpError
		if errors.As(err, &ne) && time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return err
	}
}

// servePeer handles one inbound connection from a lower-id member: the
// mTLS leaf identity must match the claimed From, the share must verify
// against the sender's commitments, and this member replies with its own
// commitments and share evaluation for that peer.
func (d *DkgNode) servePeer(conn net.Conn, errc chan<- error) {
	defer conn.Close()
	if err := serveFrames(conn, d.ID, func(m CouncilMsg) (CouncilMsg, error) {
		return d.handleFrame(conn, m)
	}); err != nil {
		errc <- err
	}
}

func (d *DkgNode) handleFrame(conn net.Conn, m CouncilMsg) (CouncilMsg, error) {
	if m.Kind != dkgExchange || !bytes.Equal(m.Session, d.session) {
		return CouncilMsg{}, errors.New("dkg: bad session frame")
	}
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return CouncilMsg{}, errors.New("dkg: not a TLS connection")
	}
	state := tconn.ConnectionState()
	if len(state.PeerCertificates) == 0 ||
		VerifyPeerIdentity(state.PeerCertificates[0], m.From) != nil {
		return CouncilMsg{}, errors.New("dkg: peer identity mismatch")
	}
	if err := d.recordPeer(m.From, m.Commits, m.ShareVal); err != nil {
		return CouncilMsg{}, err
	}
	return CouncilMsg{
		Kind: dkgExchange, Session: d.session, From: d.ID,
		Commits: d.ownHex, ShareVal: scalarBytes(d.mat.Shares[m.From]),
	}, nil
}

// recordPeer validates and stores one peer's exchange, or fails the whole
// ceremony: the share must be a valid scalar and lie on the sender's
// commitment vector at this member's index (Feldman verification — a
// corrupted peer is caught here, not at signing time).
func (d *DkgNode) recordPeer(pid string, hexCommits []string, shareVal []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, seen := d.received[pid]; seen {
		return errors.New("dkg: duplicate exchange from " + pid)
	}
	pts, err := parsePoints(hexCommits)
	if err != nil {
		return err
	}
	if len(pts) != d.T {
		return fmt.Errorf("dkg: commitment vector from %s has %d points, want %d", pid, len(pts), d.T)
	}
	val, err := scalarFromBytes(shareVal)
	if err != nil || val.Sign() <= 0 || val.Cmp(fl) >= 0 {
		return errors.New("dkg: bad share value")
	}
	if !ShareVerifies(pts, memberX(d.ID), val) {
		return errors.New("dkg: peer share fails commitment verification")
	}
	d.peerCommits[pid] = hexCommits
	d.received[pid] = val
	d.done++
	return nil
}

// finish sums the verified pieces into the member's share: the own
// material plus every received evaluation (each verified at record time),
// combined by DkgFinalize. The group key is the sum of every member's C_0
// point — public, and provably the same on each member.
func (d *DkgNode) finish() (ed25519.PublicKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	all := map[string]*DkgMaterial{d.ID: d.mat}
	for pid, hexC := range d.peerCommits {
		pts, err := parsePoints(hexC)
		if err != nil {
			return nil, err
		}
		all[pid] = &DkgMaterial{ID: pid, Commits: pts, Shares: map[string]*big.Int{d.ID: d.received[pid]}}
	}
	signer, group, err := DkgFinalize(d.ID, all)
	if err != nil {
		return nil, err
	}
	signer.GlobalVK = DkgGlobalCommitments(all)
	d.signer = signer
	return group, nil
}

// DkgGlobalCommitments is the summed commitment vector per participant
// (each entry the full global vector — the share-file GlobalVK format).
func DkgGlobalCommitments(all map[string]*DkgMaterial) []DkgCommitJSON {
	global := DkgGlobalVK(all)
	if len(global) == 0 {
		return nil
	}
	gv := make([]DkgCommitJSON, 0, len(all))
	for _, m := range all {
		pts := make([]string, len(global))
		for i, c := range global {
			pts[i] = hex.EncodeToString(encode(c))
		}
		gv = append(gv, DkgCommitJSON{ID: m.ID, Commits: pts})
	}
	return gv
}

// DkgGlobalVK sums every participant's commitment vector — the share-file
// VK so FrostShareFile.Signer() verifies the share against the group.
func DkgGlobalVK(all map[string]*DkgMaterial) []point {
	var out []point
	for _, m := range all {
		if out == nil {
			out = append([]point(nil), m.Commits...)
			continue
		}
		if len(m.Commits) != len(out) {
			return nil
		}
		for k, p := range m.Commits {
			out[k] = pointAdd(out[k], p)
		}
	}
	return out
}
