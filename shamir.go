package trustorchestrator

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// p = 2^256 - 189, a standard large prime. Shamir over GF(p) needs the
// secret < p: every ed25519 seed qualifies except the 189 values of 2^256
// in [2^256-189, 2^256-1] (probability 2^-247), which are rejected below
// rather than silently shared wrong.
var p = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(189))

// Shard is one (x, f(x)) point of the Shamir polynomial (FR4.1). Len is the
// original secret length: big.Int round-trips strip leading zero bytes, and
// Join must pad back to it (a seed 0x00.. is a valid ed25519 seed).
type Shard struct {
	X   *big.Int `json:"x"`
	Y   *big.Int `json:"y"`
	Len int      `json:"len,omitempty"`
}

// ShamirSplit splits secret into n shards; any k reconstruct it (3-of-5 in
// the council). Polynomial over GF(2^256-189), stdlib big.Int only.
func ShamirSplit(secret []byte, n, k int) ([]*Shard, error) {
	if k > n || k < 1 {
		return nil, errors.New("shamir: need 1 <= k <= n")
	}
	s := new(big.Int).SetBytes(secret)
	if s.Cmp(p) >= 0 {
		return nil, fmt.Errorf("shamir: secret must be < 2^256-189 (got %d bytes)", len(secret))
	}
	coeff := make([]*big.Int, k-1)
	for i := range coeff {
		c, err := rand.Int(rand.Reader, p)
		if err != nil {
			return nil, err
		}
		coeff[i] = c
	}
	shards := make([]*Shard, n)
	for x := 1; x <= n; x++ {
		shards[x-1] = &Shard{X: big.NewInt(int64(x)), Y: evalPoly(coeff, s, big.NewInt(int64(x))), Len: len(secret)}
	}
	return shards, nil
}

func evalPoly(coeff []*big.Int, s, x *big.Int) *big.Int {
	acc := new(big.Int).Set(s)
	xp := new(big.Int).Set(x)
	for _, c := range coeff {
		acc.Add(acc, new(big.Int).Mul(c, xp))
		acc.Mod(acc, p)
		xp.Mul(xp, x)
		xp.Mod(xp, p)
	}
	return acc
}

// ShamirJoin reconstructs the secret from k points via Lagrange at x=0.
func ShamirJoin(pts []*Shard) ([]byte, error) {
	if len(pts) == 0 {
		return nil, errors.New("shamir: no shards")
	}
	seen := map[string]bool{}
	for _, pt := range pts {
		if pt == nil || pt.X == nil || pt.Y == nil {
			return nil, errors.New("shamir: nil shard")
		}
		if seen[pt.X.String()] {
			return nil, errors.New("shamir: duplicate x")
		}
		seen[pt.X.String()] = true
	}
	secret := new(big.Int)
	for j, pj := range pts {
		num, den := big.NewInt(1), big.NewInt(1)
		for m, pm := range pts {
			if m == j {
				continue
			}
			num.Mul(num, pm.X)
			num.Mod(num, p)
			den.Mul(den, new(big.Int).Sub(pm.X, pj.X))
			den.Mod(den, p)
		}
		inv := new(big.Int).ModInverse(den, p)
		if inv == nil {
			return nil, errors.New("shamir: singular denominator")
		}
		term := new(big.Int).Mul(pj.Y, num)
		term.Mul(term, inv)
		term.Mod(term, p)
		secret.Add(secret, term)
		secret.Mod(secret, p)
	}
	b := secret.Bytes()
	if n := pts[0].Len; n > len(b) { // restore leading zeros stripped by big.Int
		pad := make([]byte, n)
		copy(pad[n-len(b):], b)
		b = pad
	}
	return b, nil
}

func (s *Shard) Marshal() ([]byte, error) { return json.Marshal(s) }
