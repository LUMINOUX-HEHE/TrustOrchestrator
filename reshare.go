package trustorchestrator

// reshare.go — membership rotation with a FIXED group key ("verified
// resharing", the ABI-style share redistribution). The council can swap
// members in and out without rebuilding the key: the recovery trust anchor
// (group public key) never changes, so every gateway's --council-pub stays
// valid across rotations.
//
// Math: the t old members S re-share. Each i ∈ S weights its share by its
// Lagrange coefficient λ_i over S, splits λ_i·y_i into a fresh
// degree-(t'-1) polynomial g_i (Feldman commitments G_{i,k} published),
// and sends g_i(j) to every member of the new index set (existing members
// receive refreshed shares too). New member j sums the verified sub-shares:
//
//	y'_j = Σ_{i∈S} g_i(j)      F(x) = Σ_i g_i(x), F(0) = Σ_i λ_i·y_i = y
//
// so the new shares are points on a fresh polynomial with the SAME secret.
// Removed members' old shares lie on the old polynomial and are dead:
// mixing them with new shares fails interpolation.
//
// Every received sub-share is verified against the sender's commitments
// (ShareVerifies) before it is accepted. A rotated-in member needs t old
// members to cooperate — that is the price of keeping the group key.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"sort"
)

// ReshareCommit is the public output of one old member's split: its
// Feldman commitments G_0..G_{t'-1} for the sub-polynomial g_i.
type ReshareCommit struct {
	From    string   `json:"from"`
	Commits []string `json:"commits"` // hex points, G_0 = λ_i·y_i·B
}

// ReshareSplit is the old-member side: split share y_i (weighted by λ_i
// over oldSet) into sub-shares for every index in newSet. Returns the
// commitment (broadcast to all) and the sub-share per new index (sent to
// each new member directly).
func ReshareSplit(me string, y *big.Int, oldSet, newSet []int, tNew int) (*ReshareCommit, map[int]*big.Int, error) {
	if y == nil || y.Sign() <= 0 || y.Cmp(fl) >= 0 {
		return nil, nil, errors.New("reshare: bad share")
	}
	if tNew < 1 || tNew > len(newSet) {
		return nil, nil, errors.New("reshare: bad new threshold")
	}
	xi := memberX(me)
	if xi == 0 {
		return nil, nil, errors.New("reshare: bad member id")
	}
	a0 := new(big.Int).Mul(lagrange(xi, oldSet), y)
	a0.Mod(a0, fl)
	coeff := make([]*big.Int, tNew-1)
	commit := make([]point, tNew)
	commit[0] = scalarMult(a0, basePoint)
	for i := range coeff {
		c, err := randomScalar()
		if err != nil {
			return nil, nil, err
		}
		coeff[i] = c
		commit[i+1] = scalarMult(c, basePoint)
	}
	shares := make(map[int]*big.Int, len(newSet))
	for _, j := range newSet {
		shares[j] = evalPolyL(coeff, a0, big.NewInt(int64(j)))
	}
	hexC := make([]string, len(commit))
	for i, p := range commit {
		hexC[i] = hex.EncodeToString(encode(p))
	}
	return &ReshareCommit{From: me, Commits: hexC}, shares, nil
}

// ReshareCombine is the new-member side: verify every received sub-share
// against its sender's commitments, sum them into the new share y'_j, and
// return a FrostSigner whose VK is the summed commitment vector (so the
// share file round-trips through FrostShareFile.Signer). The group key is
// unchanged — it is whatever the council already published.
func ReshareCombine(me string, newIndex int, commits map[string]*ReshareCommit, subShares map[string]*big.Int, groupPub ed25519.PublicKey) (*FrostSigner, error) {
	if newIndex <= 0 {
		return nil, errors.New("reshare: bad new index")
	}
	if len(commits) == 0 || len(commits) != len(subShares) {
		return nil, errors.New("reshare: commit/share count mismatch")
	}
	froms := make([]string, 0, len(commits))
	for from := range commits {
		froms = append(froms, from)
	}
	sort.Strings(froms) // deterministic sum and verification order
	y := new(big.Int)
	var combined []point
	for _, from := range froms {
		pts, err := parsePoints(commits[from].Commits)
		if err != nil {
			return nil, err
		}
		g, ok := subShares[from]
		if !ok || g == nil {
			return nil, errors.New("reshare: missing sub-share from " + from)
		}
		if !ShareVerifies(pts, newIndex, g) {
			return nil, errors.New("reshare: unverifiable sub-share from " + from)
		}
		if len(pts) > 0 && len(combined) > 0 && len(pts) != len(combined) {
			return nil, errors.New("reshare: commitment length mismatch")
		}
		if combined == nil {
			combined = make([]point, len(pts))
		}
		for k, p := range pts {
			if combined[k].X == nil {
				combined[k] = p
			} else {
				combined[k] = pointAdd(combined[k], p)
			}
		}
		y.Add(y, g)
	}
	y.Mod(y, fl)
	return &FrostSigner{
		ID: me, X: newIndex, Share: y,
		GroupPub: append([]byte(nil), groupPub...),
		PubShare: encode(scalarMult(y, basePoint)),
		VK:       combined,
	}, nil
}
