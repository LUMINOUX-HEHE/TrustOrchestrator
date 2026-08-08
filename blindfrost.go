package trustorchestrator

// blindfrost.go — threshold blind signatures over the FROST core (the
// audit-transparency primitive: a council threshold-signs an opaque
// attestation and cannot recognize the resulting signature).
//
// Flow (two rounds, the same commitment wire as FROST — signer code does
// NOT change; only the challenge and the message-input differ):
//
//	1. the t signers commit (D_i, E_i) as usual; the user collects them.
//	2. the user picks blinders (a, b) and a message-blinder r and computes
//	   m'   = H("to-blind" ‖ m ‖ r)          (binding-factor input: the
//	                                         signers never see the true m)
//	   R    = Σ_i (D_i + ρ_i·E_i)            (ρ over the original commits)
//	   R'   = R + a·B + b·X
//	   c    = H(R' ‖ X ‖ m)                  (true-message challenge)
//	   c'   = (c + b) mod L  — what the signers sign
//	3. each signer computes z_i = d_i + ρ_i·e_i + c'·λ_i·x_i — the ordinary
//	   FROST share equation with the blinded challenge.
//	4. the user sums z = Σ z_i (each partial verified against its pubshare)
//	   and unblinds s' = z + a. The signature (R' ‖ s') is an ordinary
//	   Ed25519 signature: c = H(R' ‖ X ‖ m) ⟹ s'·B = R' + c·X — it verifies
//	   under crypto/ed25519 against the group key, and no signer can link
//	   the transcript (m', c', commitments) to the published (R', s').
//
// Security ceiling (read before productizing): challenge-blinded Schnorr
// resists one-more forgery only under concurrency restrictions and the
// algebraic-group-model assumptions of the gold-standard construction
// (ePrint 2019/877); this variant keeps FROST's binding factor ρ as the
// Drijvers-attack mitigation and MUST be driven strictly sequentially for
// the same signer set — the council member server already enforces one
// pending FROST session, and FrostSigner.Commit is single-use. Wire up
// concurrent blind sessions only with a proven construction.

import (
	"crypto/ed25519"
	"errors"
	"math/big"
)

// BlindState is the user side of one blind round. The signers' view is
// (commits, m', c') and nothing else.
type BlindState struct {
	mBlind []byte   // binding-factor input the signers see (blinded m)
	cPrime *big.Int // blinded challenge the signers sign
	a      *big.Int // scalar unblinder
	Rp     point    // blinded aggregate nonce R' (the signature's R)
}

// BlindSetup computes the blinded transcript for a set of commitments,
// returning the state needed to finish signing and the blinded challenge c'
// to hand to the signers (with the blinded message m' — see
// BlindTranscript). m stays out of the wire; only the user holds it.
func BlindSetup(groupPub ed25519.PublicKey, m []byte, commits map[string][]byte) (*BlindState, []byte, error) {
	if len(commits) == 0 {
		return nil, nil, errors.New("blind: need commitments")
	}
	r, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	a, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	b, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	mBlind := scalarBytes(hashToScalar([]byte("to-blind"), m, scalarBytes(r)))
	R, err := aggregateNonce(groupPub, mBlind, commits)
	if err != nil {
		return nil, nil, err
	}
	X, err := decodePoint(groupPub)
	if err != nil {
		return nil, nil, err
	}
	Rp := pointAdd(R, pointAdd(scalarMult(a, basePoint), scalarMult(b, X)))
	c := hashToScalar(encode(Rp), groupPub, m)
	cPrime := new(big.Int).Add(c, b)
	cPrime.Mod(cPrime, fl)
	return &BlindState{mBlind: mBlind, cPrime: cPrime, a: a, Rp: Rp}, scalarBytes(cPrime), nil
}

// Transcript builds the signer-side signing context for this blind round:
// the blinded message feeds the binding factors, the blinded challenge is
// the C slot. SignShare needs nothing else (its R field is informational).
func (bs *BlindState) Transcript(commits map[string][]byte, xs map[string]int) *FrostTranscript {
	return &FrostTranscript{M: bs.mBlind, Commits: commits, Xs: xs, C: scalarBytes(bs.cPrime)}
}

// Unblind adds the scalar blinder to the aggregated shares and returns the
// final Ed25519-format signature (R' ‖ s'), verifiable with crypto/ed25519
// against the group key under the true message.
func (bs *BlindState) Unblind(aggregated []byte) ([]byte, error) {
	if len(aggregated) != ed25519.SignatureSize {
		return nil, errors.New("blind: bad aggregate")
	}
	zs, err := scalarFromBytes(aggregated[32:])
	if err != nil {
		return nil, err
	}
	s := new(big.Int).Add(zs, bs.a)
	s.Mod(s, fl)
	out := append([]byte(nil), encode(bs.Rp)...)
	return append(out, scalarBytes(s)...), nil
}

// BlindRound is the convenience full two-round blind flow in-process: every
// signer commits, the user blinds, each signer produces its share under the
// blinded challenge, and the signature aggregates — then verifies under
// crypto/ed25519. Use in place of FrostRound wherever the signers must not
// recognize the signature (audit attestations, transparency proofs).
func BlindRound(groupPub ed25519.PublicKey, signers []*FrostSigner, m []byte) ([]byte, error) {
	if len(signers) < 2 {
		return nil, errors.New("blind: need >= 2 signers")
	}
	pubs := map[string]ed25519.PublicKey{}
	xs := map[string]int{}
	commits := map[string][]byte{}
	for _, s := range signers {
		pubs[s.ID] = s.PubShare
		xs[s.ID] = s.X
		de, err := s.Commit()
		if err != nil {
			return nil, err
		}
		commits[s.ID] = de
	}
	agg := NewFrostAggregator(groupPub, pubs)
	agg.SetXs(xs)
	for id, de := range commits {
		if err := agg.AddCommit(id, de); err != nil {
			return nil, err
		}
	}
	bs, cPrime, err := BlindSetup(groupPub, m, commits)
	if err != nil {
		return nil, err
	}
	agg.UseBlindedChallenge(cPrime, bs.Rp, bs.mBlind)
	trans := bs.Transcript(commits, xs)
	for _, s := range signers {
		z, err := s.SignShare(trans)
		if err != nil {
			return nil, err
		}
		if err := agg.AddShare(s.ID, z); err != nil {
			return nil, err
		}
	}
	aggregated, err := agg.Aggregate()
	if err != nil {
		return nil, err
	}
	return bs.Unblind(aggregated)
}

// BlindVerify is ed25519.Verify: the scheme produces a standard signature.
func BlindVerify(groupPub ed25519.PublicKey, m, sig []byte) bool {
	return ed25519.Verify(groupPub, m, sig)
}
