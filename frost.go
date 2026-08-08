package trustorchestrator

// frost.go — FROST-256 threshold signatures over Ed25519, stdlib big.Int only.
//
// The aggregated signature is a STANDARD Ed25519 signature (R || S),
// verifiable with crypto/ed25519: the challenge is derived exactly like
// Ed25519 (c = SHA512(R||A||m) mod L), so the threshold output is
// indistinguishable from a single-key signature. Protocol shape follows
// draft-irtf-cfrg-frost: hiding + binding nonces, per-signer binding factor,
// per-share verification before aggregation.
//
// Safety rules (read before using):
//   - The signing flow is 2-round per message: nonce commitments first, then
//     shares. Never collapse it to one round (the known attack on one-round
//     threshold Schnorr).
//   - Nonces are single-use per (signer, message). The council session state
//     (council.go/councilnet.go) owns the pairing; do not reuse a FrostSigner
//     across concurrent sessions.
//   - There is deliberately NO reconstruction function here. Adding one is
//     the bug this file exists to prevent.
//   - Dealer mode (FrostSplit) materializes the root once at ceremony time.
//     DKG mode (DkgCeremony) never materializes it. Both produce the same
//     FrostShareFile format.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// ---- field / group constants (Ed25519) ----

// bigh parses a hex big integer (constants below exceed int64).
func bigh(h string) *big.Int {
	n, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("bad hex constant")
	}
	return n
}

var (
	fp = bigh("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed") // 2^255-19
	fl = bigh("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed") // group order L
	// fd = -121665/121666 mod p
	fd      = fieldDiv(fieldNeg(big.NewInt(121665)), big.NewInt(121666))
	sqrtM1  = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(fp, big.NewInt(1)), 2), fp) // 2^((p-1)/4) = sqrt(-1)
	identity = point{X: big.NewInt(0), Y: big.NewInt(1), Z: big.NewInt(1), T: big.NewInt(0)}
)

// base point B (the standard Ed25519 generator).
var basePoint = func() point {
	x := bigh("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a")
	y := bigh("6666666666666666666666666666666666666666666666666666666666666658")
	return point{X: x, Y: y, Z: big.NewInt(1), T: new(big.Int).Mul(x, y)}
}()

// point is an extended-coordinate Ed25519 point (x = X/Z, y = Y/Z, T = XY/Z).
type point struct{ X, Y, Z, T *big.Int }

// pointAdd is the complete addition formula (a = -1, d non-square): correct
// for doubling, identity, everything. add-2008-hwcd-3.
func pointAdd(p, q point) point {
	a := new(big.Int).Sub(p.Y, p.X)
	a.Mul(a, new(big.Int).Sub(q.Y, q.X))
	a.Mod(a, fp)
	b := new(big.Int).Add(p.Y, p.X)
	b.Mul(b, new(big.Int).Add(q.Y, q.X))
	b.Mod(b, fp)
	c := new(big.Int).Mul(p.T, q.T)
	c.Mul(c, fd)
	c.Mul(c, big.NewInt(2))
	c.Mod(c, fp)
	d := new(big.Int).Mul(p.Z, q.Z)
	d.Mul(d, big.NewInt(2))
	d.Mod(d, fp)
	e := new(big.Int).Sub(b, a)
	e.Mod(e, fp)
	f := new(big.Int).Sub(d, c)
	f.Mod(f, fp)
	g := new(big.Int).Add(d, c)
	g.Mod(g, fp)
	h := new(big.Int).Add(b, a)
	h.Mod(h, fp)
	mod := func(v *big.Int) *big.Int { return v.Mod(v, fp) }
	// fresh big.Int per coordinate: sharing one would make X/Y/T/Z alias
	return point{X: mod(new(big.Int).Mul(e, f)), Y: mod(new(big.Int).Mul(g, h)), T: mod(new(big.Int).Mul(e, h)), Z: mod(new(big.Int).Mul(f, g))}
}

// scalarMult computes k*P by double-and-add (256-bit loop; k < L < 2^253).
func scalarMult(k *big.Int, P point) point {
	Q := identity
	for _, byt := range k.Bytes() {
		for i := 7; i >= 0; i-- {
			Q = pointAdd(Q, Q)
			if byt&(1<<i) != 0 {
				Q = pointAdd(Q, P)
			}
		}
	}
	return Q
}

func fieldNeg(a *big.Int) *big.Int { return new(big.Int).Sub(fp, new(big.Int).Mod(a, fp)) }

func fieldDiv(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mod(a, fp),
		new(big.Int).ModInverse(new(big.Int).Mod(b, fp), fp)), fp)
}

// EncodePoint encodes a commitment point in standard Ed25519 form
// (32-byte LE y, top bit = x parity). Exported for share-file writers.
func EncodePoint(p point) []byte { return encode(p) }

// encode encodes a point in standard Ed25519 form: 32-byte LE y, top bit =
// x parity. Identical to crypto/ed25519's public-key encoding.
func encode(p point) []byte {
	z := new(big.Int).ModInverse(p.Z, fp)
	x := new(big.Int).Mul(p.X, z)
	x.Mod(x, fp)
	y := new(big.Int).Mul(p.Y, z)
	y.Mod(y, fp)
	b := make([]byte, 32)
	fillLE(b, y)
	if x.Bit(0) == 1 {
		b[31] |= 0x80
	}
	return b
}

func fillLE(b []byte, v *big.Int) {
	v = new(big.Int).Set(v)
	acc := new(big.Int)
	for i := range b {
		acc.Rsh(v, uint(8*i))
		b[i] = byte(acc.Uint64())
	}
}

func leToInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(reverse(b))
}

func reverse(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return r
}

// decode parses an Ed25519 point; malformed input fails cleanly.
func decodePoint(b []byte) (point, error) {
	if len(b) != 32 {
		return point{}, errors.New("frost: point must be 32 bytes")
	}
	sign := b[31] >> 7
	c := append([]byte(nil), b...)
	c[31] &= 0x7f
	y := leToInt(c)
	if y.Cmp(fp) >= 0 {
		return point{}, errors.New("frost: y >= p")
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, fp)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, fp)
	v := new(big.Int).Mul(fd, y2)
	v.Add(v, big.NewInt(1))
	v.Mod(v, fp)
	inv := new(big.Int).ModInverse(v, fp)
	if inv == nil {
		return point{}, errors.New("frost: invalid point (singular)")
	}
	x2 := new(big.Int).Mul(u, inv)
	x2.Mod(x2, fp)
	exp := new(big.Int).Rsh(new(big.Int).Add(fp, big.NewInt(3)), 3) // (p+3)/8
	x := new(big.Int).Exp(x2, exp, fp)
	if new(big.Int).Mul(x, x).Mod(new(big.Int).Mul(x, x), fp).Cmp(x2) != 0 {
		x.Mul(x, sqrtM1)
		x.Mod(x, fp)
		if new(big.Int).Mul(x, x).Mod(new(big.Int).Mul(x, x), fp).Cmp(x2) != 0 {
			return point{}, errors.New("frost: invalid point (not on curve)")
		}
	}
	if uint(x.Bit(0)) != uint(sign) {
		x.Sub(fp, x)
	}
	xy := new(big.Int).Mul(x, y)
	xy.Mod(xy, fp)
	return point{X: x, Y: y, Z: big.NewInt(1), T: xy}, nil
}

// ed25519Scalar derives the clamped signing scalar a from an Ed25519 seed,
// exactly as crypto/ed25519 does: a = clamp(SHA512(seed)[0:32]).
func ed25519Scalar(seed []byte) *big.Int {
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	return leToInt(h[:32])
}

// ---- scalars ----

func randomScalar() (*big.Int, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return new(big.Int).Mod(leToInt(b), fl), nil
}

// hashToScalar = SHA512(parts...) as LE integer mod L — the exact Ed25519
// challenge derivation, so threshold output verifies with crypto/ed25519.
func hashToScalar(parts ...[]byte) *big.Int {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return new(big.Int).Mod(leToInt(h.Sum(nil)), fl)
}

func scalarBytes(s *big.Int) []byte {
	b := make([]byte, 32)
	fillLE(b, new(big.Int).Mod(s, fl))
	return b
}

func scalarFromBytes(b []byte) (*big.Int, error) {
	if len(b) != 32 {
		return nil, errors.New("frost: scalar must be 32 bytes")
	}
	return new(big.Int).Mod(leToInt(b), fl), nil
}

// ---- share files ----

// FrostShareFile is one member's on-disk share. Dealer mode: VK is the
// dealer's Feldman commitments (verify this share). DKG mode: GlobalVK is
// every participant's commitments (verify this share; pubkey shares derive
// from the same commitments).
type FrostShareFile struct {
	ID       string          `json:"id"`
	X        int             `json:"x"`
	Y        *big.Int        `json:"y"`         // f(x) mod L — the signing secret
	GroupPub []byte          `json:"group_pub"` // A (32 bytes)
	PubShare []byte          `json:"pub_share"` // A_i = share*B (32 bytes)
	VK       []string        `json:"vk,omitempty"`
	GlobalVK []DkgCommitJSON `json:"global_vk,omitempty"`
}

type DkgCommitJSON struct {
	ID      string   `json:"id"`
	Commits []string `json:"commits"` // hex points C_0..C_{t-1}
}

func (f *FrostShareFile) Marshal() ([]byte, error) { return json.Marshal(f) }

func parsePoints(hexList []string) ([]point, error) {
	pts := make([]point, 0, len(hexList))
	for _, s := range hexList {
		raw, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("frost: bad commitment hex: %w", err)
		}
		p, err := decodePoint(raw)
		if err != nil {
			return nil, fmt.Errorf("frost: bad commitment point: %w", err)
		}
		pts = append(pts, p)
	}
	return pts, nil
}

// Signer loads the share into a signing participant. The share is verified
// against its commitments before it is accepted (a corrupted file fails
// cleanly, not silently).
func (f *FrostShareFile) Signer() (*FrostSigner, error) {
	if f.Y == nil || f.Y.Cmp(fl) >= 0 || f.Y.Sign() < 0 {
		return nil, errors.New("frost: bad share value")
	}
	if len(f.GroupPub) != ed25519.PublicKeySize || len(f.PubShare) != ed25519.PublicKeySize {
		return nil, errors.New("frost: bad key lengths")
	}
	s := &FrostSigner{
		ID: f.ID, X: f.X, Share: new(big.Int).Set(f.Y),
		GroupPub: append([]byte(nil), f.GroupPub...),
		PubShare: append([]byte(nil), f.PubShare...),
	}
	vk := f.VK
	if len(vk) == 0 && len(f.GlobalVK) > 0 {
		for _, g := range f.GlobalVK {
			if g.ID == f.ID {
				vk = g.Commits
			}
		}
	}
	if len(vk) > 0 {
		pts, err := parsePoints(vk)
		if err != nil {
			return nil, err
		}
		s.VK = pts
		if !ShareVerifies(pts, f.X, s.Share) {
			return nil, errors.New("frost: share fails commitment verification")
		}
	}
	return s, nil
}

// ---- dealer mode ----

// FrostSplit splits an Ed25519 seed into n t-of-n FROST shares over the
// scalar field L. The seed's public key IS the group key A: shares sign
// exactly what the seed would sign, verifiable against
// ed25519.PublicKeyFromSeed(seed). The dealer holds the seed once (ceremony
// time); after split, only the returned shares exist.
func FrostSplit(seed []byte, n, t int) ([]*FrostSigner, ed25519.PublicKey, error) {
	if t > n || t < 1 {
		return nil, nil, errors.New("frost: need 1 <= t <= n")
	}
	a := ed25519Scalar(seed)
	coeff := make([]*big.Int, t-1)
	for i := range coeff {
		c, err := randomScalar()
		if err != nil {
			return nil, nil, err
		}
		coeff[i] = c
	}
	commit := make([]point, t)
	commit[0] = scalarMult(a, basePoint)
	for i, c := range coeff {
		commit[i+1] = scalarMult(c, basePoint)
	}
	signers := make([]*FrostSigner, n)
	for x := 1; x <= n; x++ {
		share := evalPolyL(coeff, a, big.NewInt(int64(x)))
		signers[x-1] = &FrostSigner{
			ID: fmt.Sprintf("M%d", x), X: x, Share: share,
			GroupPub: encode(commit[0]), PubShare: encode(scalarMult(share, basePoint)),
			VK: commit,
		}
	}
	return signers, encode(commit[0]), nil
}

// evalPolyL evaluates the secret-sharing polynomial at x (over L).
func evalPolyL(coeff []*big.Int, secret, x *big.Int) *big.Int {
	acc := new(big.Int).Set(secret)
	xp := new(big.Int).Set(x)
	for _, c := range coeff {
		acc.Add(acc, new(big.Int).Mul(c, xp))
		acc.Mod(acc, fl)
		xp.Mul(xp, x)
		xp.Mod(xp, fl)
	}
	return acc
}

// ShareVerifies checks a share against Feldman commitments:
// share*B == Σ_j C_j*x^j.
func ShareVerifies(commit []point, x int, share *big.Int) bool {
	acc := identity
	xp := big.NewInt(1) // x^0 for C_0, then x, x^2, ...
	for _, c := range commit {
		acc = pointAdd(acc, scalarMult(xp, c))
		xp.Mul(xp, big.NewInt(int64(x)))
	}
	return string(encode(acc)) == string(encode(scalarMult(share, basePoint)))
}

// ---- DKG mode (no dealer, no root anywhere) ----

// DkgMaterial is one participant's output of DkgGenerate: its commitments
// and the share it computed for every participant (itself included).
type DkgMaterial struct {
	ID      string
	Commits []point
	Shares  map[string]*big.Int
}

// DkgGenerate creates participant id's polynomial, commitments and shares
// for all n participants (Feldman VSS).
func DkgGenerate(id string, n, t int) (*DkgMaterial, error) {
	if t > n || t < 1 {
		return nil, errors.New("frost: need 1 <= t <= n")
	}
	a, err := randomScalar()
	if err != nil {
		return nil, err
	}
	coeff := make([]*big.Int, t-1)
	for i := range coeff {
		c, err := randomScalar()
		if err != nil {
			return nil, err
		}
		coeff[i] = c
	}
	commit := make([]point, t)
	commit[0] = scalarMult(a, basePoint)
	for i, c := range coeff {
		commit[i+1] = scalarMult(c, basePoint)
	}
	shares := map[string]*big.Int{}
	for x := 1; x <= n; x++ {
		shares[fmt.Sprintf("M%d", x)] = evalPolyL(coeff, a, big.NewInt(int64(x)))
	}
	return &DkgMaterial{ID: id, Commits: commit, Shares: shares}, nil
}

// DkgFinalize combines all participants' materials into participant id's
// final share and the group public key. Every received share is verified
// against its sender's commitments first.
func DkgFinalize(id string, all map[string]*DkgMaterial) (*FrostSigner, ed25519.PublicKey, error) {
	if _, ok := all[id]; !ok {
		return nil, nil, fmt.Errorf("frost: no material for %s", id)
	}
	share := new(big.Int)
	group := identity
	for _, m := range all {
		group = pointAdd(group, m.Commits[0])
		s, ok := m.Shares[id]
		if !ok {
			return nil, nil, fmt.Errorf("frost: %s missing share for %s", m.ID, id)
		}
		if !ShareVerifies(m.Commits, memberX(id), s) {
			return nil, nil, fmt.Errorf("frost: %s sent an invalid share", m.ID)
		}
		share.Add(share, s)
	}
	share.Mod(share, fl)
	return &FrostSigner{
		ID: id, X: memberX(id), Share: share,
		GroupPub: encode(group), PubShare: encode(scalarMult(share, basePoint)),
	}, encode(group), nil
}

// memberX maps a participant id ("M1".."Mn") to its polynomial evaluation
// point. Canonical: index digits, verified against the id syntax at use.
func memberX(id string) int {
	if len(id) < 2 || id[0] != 'M' {
		return 0
	}
	var x int
	for _, r := range id[1:] {
		if r < '0' || r > '9' {
			return 0
		}
		x = x*10 + int(r-'0')
	}
	return x
}

// DkgCeremony runs n in-process participants and returns their final shares
// plus the group key. Nothing ever materialized the root. Used by the
// ceremony CLI (air-gapped machine) and tests. ponytail: all participants on
// one machine = trust the ceremony machine; a distributed ceremony over the
// council wire is the same math with messages — add when the ceremony
// machine itself is a threat.
func DkgCeremony(n, t int) ([]*FrostSigner, ed25519.PublicKey, error) {
	mat := map[string]*DkgMaterial{}
	for i := 1; i <= n; i++ {
		m, err := DkgGenerate(fmt.Sprintf("M%d", i), n, t)
		if err != nil {
			return nil, nil, err
		}
		mat[m.ID] = m
	}
	var group ed25519.PublicKey
	signers := make([]*FrostSigner, 0, n)
	for _, m := range mat {
		s, g, err := DkgFinalize(m.ID, mat)
		if err != nil {
			return nil, nil, err
		}
		signers = append(signers, s)
		group = g
	}
	// every signer's share is the SUM of all participants' polynomial
	// evaluations, so its share file must verify against the summed global
	// commitments, not its own.
	global := make([]point, t)
	for _, m := range mat {
		for j, c := range m.Commits {
			if global[j].X == nil {
				global[j] = c
			} else {
				global[j] = pointAdd(global[j], c)
			}
		}
	}
	gv := make([]DkgCommitJSON, 0, n)
	for _, m := range mat {
		pts := make([]string, len(global))
		for i, c := range global {
			pts[i] = hex.EncodeToString(encode(c))
		}
		gv = append(gv, DkgCommitJSON{ID: m.ID, Commits: pts})
	}
	for _, s := range signers {
		s.GlobalVK = gv
	}
	return signers, group, nil
}

// ---- FROST signing ----

// FrostSigner is one threshold participant. Stateful: Commit() then
// SignShare() for ONE message; a fresh signer (or fresh nonce state) is
// required per message.
type FrostSigner struct {
	ID       string
	X        int // participant index: f(x) is this signer's share
	Share    *big.Int
	GroupPub ed25519.PublicKey
	PubShare ed25519.PublicKey
	VK       []point
	GlobalVK []DkgCommitJSON

	d, e *big.Int
	used bool
}

// Commit generates this signer's hiding and binding nonces and returns the
// commitment (D || E, 64 bytes). One commitment per message.
func (s *FrostSigner) Commit() ([]byte, error) {
	if s.used {
		return nil, errors.New("frost: signer reused for a second message")
	}
	s.used = true
	var err error
	if s.d, err = randomScalar(); err != nil {
		return nil, err
	}
	if s.e, err = randomScalar(); err != nil {
		return nil, err
	}
	return append(encode(scalarMult(s.d, basePoint)), encode(scalarMult(s.e, basePoint))...), nil
}

// FrostTranscript is the full signing context both sides derive from:
// message, all commitments, R and c. Binding factors are recomputed from the
// sorted commitments, so both sides agree regardless of exchange order.
type FrostTranscript struct {
	M       []byte
	Commits map[string][]byte // id -> D||E (64 bytes)
	Xs      map[string]int    // id -> participant index (for Lagrange)
	R       []byte            // 32
	C       []byte            // 32
}

func (t *FrostTranscript) sortedIDs() []string {
	ids := make([]string, 0, len(t.Commits))
	for id := range t.Commits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// bindingFactor = SHA512("to-binding" || A || m || commits(sorted) || id) mod L.
func (t *FrostTranscript) bindingFactor(groupPub ed25519.PublicKey, id string) *big.Int {
	parts := [][]byte{[]byte("to-binding"), groupPub, t.M}
	for _, sid := range t.sortedIDs() {
		parts = append(parts, t.Commits[sid])
	}
	parts = append(parts, []byte(id))
	return hashToScalar(parts...)
}

// lagrange computes participant xi's interpolation coefficient over the
// signing set xs (mod L): λ_i = ∏_{j≠i} x_j / (x_j - x_i).
func lagrange(xi int, xs []int) *big.Int {
	num, den := big.NewInt(1), big.NewInt(1)
	for _, xj := range xs {
		if xj == xi {
			continue
		}
		num.Mul(num, big.NewInt(int64(xj)))
		den.Mul(den, big.NewInt(int64(xj-xi)))
	}
	num.Mod(num, fl)
	den.Mod(den, fl)
	inv := new(big.Int).ModInverse(den, fl)
	prod := new(big.Int).Mul(num, inv)
	return prod.Mod(prod, fl)
}

// participantXs extracts the signing set's x-coordinates from a transcript.
func participantXs(t *FrostTranscript) []int {
	xs := make([]int, 0, len(t.Xs))
	for _, sid := range t.sortedIDs() {
		xs = append(xs, t.Xs[sid])
	}
	return xs
}

// SignShare returns this signer's partial signature
// z_i = d + ρe + c*λ_i*share, where λ_i is the Lagrange interpolation
// coefficient over the current signing set.
func (s *FrostSigner) SignShare(t *FrostTranscript) ([]byte, error) {
	if s.d == nil || s.e == nil {
		return nil, errors.New("frost: no commitment made")
	}
	if len(t.Commits) == 0 || len(t.Xs) == 0 {
		return nil, errors.New("frost: empty transcript")
	}
	rho := t.bindingFactor(s.GroupPub, s.ID)
	rho.Mul(rho, s.e)
	rho.Add(rho, s.d)
	c := new(big.Int).Mod(leToInt(t.C), fl)
	lam := lagrange(s.X, participantXs(t))
	rho.Add(rho, new(big.Int).Mul(c, new(big.Int).Mul(lam, s.Share)))
	rho.Mod(rho, fl) // rho*e is ~506 bits; reduce before encoding
	return scalarBytes(rho), nil
}

// FrostAggregator is the initiator side: collects commitments and shares,
// verifies each share against its commitment and pubkey share, and
// aggregates into a standard Ed25519 signature.
type FrostAggregator struct {
	groupPub ed25519.PublicKey
	pubs     map[string]point // A_i per signer id
	commits  map[string][]byte
	shares   map[string]*big.Int
	R        point
	c        *big.Int
	m        []byte
	xs       map[string]int
}

// SetXs records each signer's participant index, used for the Lagrange
// interpolation coefficients in share verification.
func (a *FrostAggregator) SetXs(xs map[string]int) { a.xs = xs }

// NewFrostAggregator takes the group key and each signer's pubkey share.
func NewFrostAggregator(groupPub ed25519.PublicKey, pubs map[string]ed25519.PublicKey) *FrostAggregator {
	pts := map[string]point{}
	for id, b := range pubs {
		if p, err := decodePoint(b); err == nil {
			pts[id] = p
		}
	}
	return &FrostAggregator{groupPub: groupPub, pubs: pts,
		commits: map[string][]byte{}, shares: map[string]*big.Int{}}
}

// AddCommit records one signer's D||E commitment.
func (a *FrostAggregator) AddCommit(id string, de []byte) error {
	if len(de) != 64 {
		return errors.New("frost: commitment must be 64 bytes")
	}
	if _, ok := a.pubs[id]; !ok {
		return fmt.Errorf("frost: unknown signer %s", id)
	}
	if _, dup := a.commits[id]; dup {
		return fmt.Errorf("frost: duplicate commitment %s", id)
	}
	a.commits[id] = append([]byte(nil), de...)
	return nil
}

// ComputeChallenge derives the aggregated nonce point R and the challenge
// c = SHA512(R || A || m) from the message and ALL signer commitments. Any
// side can compute it; members use it to verify the aggregator's transcript
// before revealing their partial signature (round 2 binds to round 1).
// ponytail: binding factors hash the group key A, not each signer's A_i —
// the wire recompute cannot know other members' pubkey shares, and every
// partial is verified against ceremony-fixed pubshares anyway, so binding
// to (A, m, sorted commits, id) is equivalent here.
func ComputeChallenge(groupPub ed25519.PublicKey, m []byte, commits map[string][]byte) (r, c []byte, err error) {
	if len(commits) == 0 {
		return nil, nil, errors.New("frost: need commitments")
	}
	trans := &FrostTranscript{M: m, Commits: commits}
	R := identity
	for id, de := range commits {
		D, err := decodePoint(de[:32])
		if err != nil {
			return nil, nil, err
		}
		E, err := decodePoint(de[32:])
		if err != nil {
			return nil, nil, err
		}
		rho := trans.bindingFactor(groupPub, id)
		R = pointAdd(R, pointAdd(D, scalarMult(rho, E)))
	}
	cc := hashToScalar(encode(R), groupPub, m)
	return encode(R), scalarBytes(cc), nil
}

// Challenge derives R and c from the collected commitments. All
// commitments must be in first.
func (a *FrostAggregator) Challenge(m []byte) (r, c []byte, err error) {
	if len(a.commits) == 0 || len(a.commits) != len(a.pubs) {
		return nil, nil, fmt.Errorf("frost: need commitments from all %d signers, have %d", len(a.pubs), len(a.commits))
	}
	r, c, err = ComputeChallenge(a.groupPub, m, a.commits)
	if err != nil {
		return nil, nil, err
	}
	a.R, err = decodePoint(r)
	if err != nil {
		return nil, nil, err
	}
	a.c = new(big.Int).Mod(leToInt(c), fl)
	a.m = append([]byte(nil), m...)
	return r, c, nil
}

// AddShare verifies one partial signature z_i against the signer's
// commitment and pubkey share (z_i*B == R_i + c*A_i) before accepting it.
func (a *FrostAggregator) AddShare(id string, z []byte) error {
	zi, err := scalarFromBytes(z)
	if err != nil {
		return err
	}
	de, ok := a.commits[id]
	if !ok {
		return fmt.Errorf("frost: no commitment for %s", id)
	}
	Ai, ok := a.pubs[id]
	if !ok {
		return fmt.Errorf("frost: no pubshare for %s", id)
	}
	if a.R.X == nil {
		return errors.New("frost: challenge not computed")
	}
	if len(a.xs) != len(a.pubs) {
		return errors.New("frost: participant indices missing")
	}
	D, _ := decodePoint(de[:32])
	E, _ := decodePoint(de[32:])
	trans := &FrostTranscript{M: a.m, Commits: a.commits, Xs: a.xs}
	rho := trans.bindingFactor(a.groupPub, id)
	Ri := pointAdd(D, scalarMult(rho, E))
	lam := lagrange(a.xs[id], participantXs(trans))
	lhs := scalarMult(zi, basePoint)
	rhs := pointAdd(Ri, scalarMult(new(big.Int).Mul(a.c, lam), Ai))
	if string(encode(lhs)) != string(encode(rhs)) {
		return fmt.Errorf("frost: invalid share from %s (xs=%v lhs=%x rhs=%x rho=%s c=%s lam=%s)", id, a.xs, encode(lhs), encode(rhs), rho, a.c, lam)
	}
	a.shares[id] = zi
	return nil
}

// Aggregate sums the verified shares into the group signature (R || z),
// verifiable with crypto/ed25519 against the group public key.
func (a *FrostAggregator) Aggregate() ([]byte, error) {
	if len(a.shares) != len(a.pubs) {
		return nil, fmt.Errorf("frost: need shares from all %d signers, have %d", len(a.pubs), len(a.shares))
	}
	z := new(big.Int)
	for _, zi := range a.shares {
		z.Add(z, zi)
	}
	z.Mod(z, fl)
	return append(encode(a.R), scalarBytes(z)...), nil
}

// FrostRound is the convenience two-round flow in-process: every signer
// commits, the aggregator derives the challenge, each signer produces its
// share, and the result aggregates into a standard Ed25519 signature.
func FrostRound(groupPub ed25519.PublicKey, signers []*FrostSigner, m []byte) ([]byte, error) {
	if len(signers) < 2 {
		return nil, errors.New("frost: need >= 2 signers")
	}
	pubs := map[string]ed25519.PublicKey{}
	xs := map[string]int{}
	for _, s := range signers {
		pubs[s.ID] = s.PubShare
		xs[s.ID] = s.X
	}
	agg := NewFrostAggregator(groupPub, pubs)
	agg.SetXs(xs)
	commits := map[string][]byte{}
	for _, s := range signers {
		de, err := s.Commit()
		if err != nil {
			return nil, err
		}
		commits[s.ID] = de
	}
	for id, de := range commits {
		if err := agg.AddCommit(id, de); err != nil {
			return nil, err
		}
	}
	r, c, err := agg.Challenge(m)
	if err != nil {
		return nil, err
	}
	trans := &FrostTranscript{M: m, Commits: commits, Xs: xs, R: r, C: c}
	for _, s := range signers {
		z, err := s.SignShare(trans)
		if err != nil {
			return nil, err
		}
		if err := agg.AddShare(s.ID, z); err != nil {
			return nil, err
		}
	}
	return agg.Aggregate()
}

// ---- self-check (runnable: go test -run TestFrostSelfCheck) ----

func frostSelfCheck() error {
	// 1. base point encodes to the canonical Ed25519 generator bytes.
	want := "5866666666666666666666666666666666666666666666666666666666666666"
	if got := hex.EncodeToString(encode(basePoint)); got != want {
		return fmt.Errorf("base point encoding: %s != %s", got, want)
	}
	// 2. a seed's group pubkey equals crypto/ed25519's pubkey.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signers, groupPub, err := FrostSplit(seed, 5, 3)
	if err != nil {
		return err
	}
	if string(groupPub) != string(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		return errors.New("group pubkey != stdlib pubkey")
	}
	// 3. encode/decode round-trip on every signer's pubshare point.
	for _, s := range signers {
		p, err := decodePoint(encode(scalarMult(s.Share, basePoint)))
		if err != nil {
			return err
		}
		if string(encode(p)) != string(encode(scalarMult(s.Share, basePoint))) {
			return errors.New("encode/decode round-trip failed")
		}
	}
	// 4. threshold sign + stdlib verify; 2 signers must fail.
	m := []byte("recovery manifest")
	sig, err := FrostRound(groupPub, signers[:3], m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(groupPub, m, sig) {
		return errors.New("threshold signature fails stdlib verification")
	}
	if _, err := FrostRound(groupPub, signers[:2], m); err == nil {
		return errors.New("2-of-3 signing must fail")
	}
	// 5. tampered share must be rejected by the aggregator.
	bad := &FrostSigner{ID: signers[0].ID, Share: new(big.Int).Add(signers[0].Share, big.NewInt(1)),
		GroupPub: signers[0].GroupPub, PubShare: signers[0].PubShare}
	if _, err := FrostRound(groupPub, []*FrostSigner{bad, signers[1], signers[2]}, m); err == nil {
		return errors.New("tampered share must fail verification")
	}
	// 6. DKG ceremony produces a working group too.
	dkgSigners, dkgPub, err := DkgCeremony(5, 3)
	if err != nil {
		return err
	}
	sig2, err := FrostRound(dkgPub, dkgSigners[:3], m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(dkgPub, m, sig2) {
		return errors.New("DKG threshold signature fails stdlib verification")
	}
	return nil
}

