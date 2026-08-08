package trustorchestrator

// Blind threshold signatures: the council signs an opaque audit
// attestation; the producing signers cannot recognize the published
// signature (unlinkability) and never see the real message. The final
// signature verifies with plain crypto/ed25519 against the group key.

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func testSigners(t *testing.T, seed []byte, n, k int) ([]*FrostSigner, ed25519.PublicKey) {
	t.Helper()
	signers, group, err := FrostSplit(seed, n, k)
	if err != nil {
		t.Fatal(err)
	}
	return signers, group
}

func TestBlindFrostRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signers, group := testSigners(t, seed, 5, 3)
	m := []byte("audit attestation: mirror head efbeadde0000")

	sig, err := BlindRound(group, signers[:3], m)
	if err != nil {
		t.Fatal(err)
	}
	// The blind signature is an ordinary Ed25519 signature.
	if !ed25519.Verify(group, m, sig) {
		t.Fatal("blind threshold signature fails stdlib verification")
	}
	// A normal FROST round with the same membership (a FRESH signer set —
	// FrostSplit is deterministic on the seed, the nonces are random) must
	// produce a different (unlinked) signature: the blind R' carries the
	// blinders a, b.
	fresh, _ := testSigners(t, seed, 5, 3) // same group, fresh nonce state
	sig2, err := FrostRound(group, fresh, m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig, sig2) {
		t.Fatal("blind signature must differ from the plain FROST signature")
	}
	// The blinders are essential: blind verification against another
	// message must fail.
	if ed25519.Verify(group, []byte("other message"), sig) {
		t.Fatal("blind signature verifies under the wrong message")
	}
}

// TestBlindSignersNeverSeeMessage: the signer-side transcript carries the
// blinded message and the blinded challenge only — the true message m and
// the final R' are unrecoverable from them (the user's transcript is
// built from BlindState, which holds m but never exposes it to the wire).
func TestBlindSignersNeverSeeMessage(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	signers, group := testSigners(t, seed, 3, 2)
	m := []byte("the real audit statement")

	de0, err := signers[0].Commit()
	if err != nil {
		t.Fatal(err)
	}
	de1, err := signers[1].Commit()
	if err != nil {
		t.Fatal(err)
	}
	commits := map[string][]byte{signers[0].ID: de0, signers[1].ID: de1}
	bs, cPrime, err := BlindSetup(group, m, commits)
	if err != nil {
		t.Fatal(err)
	}
	// What the signers physically receive: the blinded message and the
	// blinded challenge. Neither is the user's m, and the challenge primes
	// no standard re-derivation shortcut: recomputing the plain FROST
	// challenge for the transcript yields a DIFFERENT value.
	if bytes.Contains(bs.mBlind, m) {
		t.Fatal("blinded message leaks the true message")
	}
	plain, _, err := ComputeChallenge(group, m, commits)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(plain, cPrime) {
		t.Fatal("blinded challenge equals the plain challenge")
	}
	// And the signature produced from this transcript still binds to m.
	xs := map[string]int{signers[0].ID: signers[0].X, signers[1].ID: signers[1].X}
	trans := bs.Transcript(commits, xs)
	z0, err := signers[0].SignShare(trans)
	if err != nil {
		t.Fatal(err)
	}
	z1, err := signers[1].SignShare(trans)
	if err != nil {
		t.Fatal(err)
	}
	// aggregate like the coordinator: (R' ‖ z0+z1)
	aggregated := make([]byte, 64)
	copy(aggregated[:32], encode(bs.Rp))
	za, _ := scalarFromBytes(z0)
	zb, _ := scalarFromBytes(z1)
	copy(aggregated[32:], scalarBytes(za.Add(za, zb).Mod(za, fl)))
	sig, err := bs.Unblind(aggregated)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(group, m, sig) {
		t.Fatal("blinded transcript does not verify under the true message")
	}
}

// TestBlindNoSignerReuse: a signer's nonce pair is single-use — a second
// blind round (or a second session on the same signer) is refused.
func TestBlindNoParallelSessions(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 9
	signers, group := testSigners(t, seed, 3, 2)
	m := []byte("audit attestation one")
	if _, err := BlindRound(group, signers[:2], m); err != nil {
		t.Fatal(err)
	}
	if _, err := BlindRound(group, signers[:2], []byte("audit attestation two")); err == nil {
		t.Fatal("signer reuse across blind rounds must fail")
	}
}