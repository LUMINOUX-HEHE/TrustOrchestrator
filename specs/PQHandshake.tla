---- MODULE PQHandshake ----
\* Formal model of the post-quantum hybrid handshake (pq.go): the session
\* key is the mix of TWO independent halves —
\*   initiator: keyI = mix( DH(pubI, dhR),     KEMENC(kemR) )
\*   responder: keyR = mix( DH(db,   pubI_dh), KEMDEC(kb, ct) )
\* Both halves must agree for the session to establish (Shor breaks the
\* DH half; ML-KEM holds under Shor — so an established session survives
\* a quantum computer if and only if BOTH halves are honest).
\*
\* The attacker (environment) rewrites any half of the in-flight material
\* before the run: the responder's DH public key (dhR), the responder's
\* KEM public key (kemR), or the ciphertext (ct). TLC explores every
\* combination. P8 = an established session requires BOTH halves to be the
\* untampered ones: rewrite any half and the two sides derive different
\* keys, the equality check fails, and the session never reaches
\* ESTABLISHED. The mutation test (PQHandshakeMutant, one-half mix)
\* shows TLC rejects a handshake that drops the KEM half.
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    MaxSteps \* bound on handshake attempts so TLC terminates

VARIABLES
    dhR, kemR, ct,  \* initiator's view of responder DH pub / KEM pub; responder's view of ct
    keyI, keyR,     \* derived session keys (NULL = failed)
    phaseI, phaseR, \* IDLE / ESTABLISHED / FAILED
    steps           \* handshake attempts (bound)

vars == <<dhR, kemR, ct, keyI, keyR, phaseI, phaseR, steps>>

NULL == "NULL"

\* Symbolic identities (abstract values; "evil" = attacker-owned).
da == "da"   \* initiator DH public key
db == "db"   \* responder DH public key
de == "de"   \* attacker DH public key (rewritten dhR)
ka == "ka"   \* responder KEM public key
kb == "kb"   \* responder KEM private key
ke == "ke"   \* attacker KEM public key (rewritten kemR)
ctAB == "ctab" \* honest ciphertext (initiator -> responder)
cte == "cte"   \* attacker ciphertext (rewritten ct)
sab == "sab"   \* honest DH shared secret (da <-> db)
sae == "sae"   \* DH shared secret with the attacker's key
sAB == "sab2"  \* honest KEM shared secret (ka <-> kb)
sE == "se"     \* KEM shared secret encapsulated to the attacker's key

\* X25519: ECDH is symmetric, and talking to the wrong public key yields a
\* valid but DIFFERENT secret (not an error) — keyI and keyR diverge.
dh(p, q) ==
    IF {p, q} = {da, db} THEN sab
    ELSE IF {p, q} = {da, de} THEN sae
    ELSE NULL

\* ML-KEM: encapsulation to the honest key gives sAB; the honest private
\* key only decapsulates the honest ciphertext (anything else fails).
KEMENC(k) == IF k = ka THEN sAB ELSE IF k = ke THEN sE ELSE NULL
KEMDEC(priv, c) == IF priv = kb /\ c = ctAB THEN sAB ELSE NULL

\* The hybrid mix: both halves required. NULL propagates — a missing half
\* can never produce a session key (this is what the mutant removes).
mix(a, b) == IF a = NULL \/ b = NULL THEN NULL ELSE <<a, b>>

Init ==
    /\ dhR = db /\ kemR = ka /\ ct = ctAB
    /\ keyI = NULL /\ keyR = NULL
    /\ phaseI = "IDLE" /\ phaseR = "IDLE"
    /\ steps = 0

\* Attacker rewrites any half of the in-flight material for a FRESH
\* handshake attempt (a rewrite can never reach the already-established
\* session — it only poisons the next run). Choosing the honest values
\* again is allowed (the honest run must stay reachable) — P8 must hold
\* under every combination.
Tamper(d, k, c) ==
    /\ d \in {db, de} /\ k \in {ka, ke} /\ c \in {ctAB, cte}
    /\ dhR' = d /\ kemR' = k /\ ct' = c
    /\ keyI' = NULL /\ keyR' = NULL
    /\ phaseI' = "IDLE" /\ phaseR' = "IDLE"
    /\ steps' = steps

\* Both sides derive their key from their own views, then compare: equal
\* non-NULL keys establish the session; anything else fails both sides.
Run ==
    /\ steps < MaxSteps
    /\ keyI' = mix(dh(da, dhR), KEMENC(kemR))
    /\ keyR' = mix(dh(db, da), KEMDEC(kb, ct))
    /\ IF keyI' = keyR' /\ keyI' /= NULL
         THEN phaseI' = "ESTABLISHED" /\ phaseR' = "ESTABLISHED"
         ELSE phaseI' = "FAILED" /\ phaseR' = "FAILED"
    /\ steps' = steps + 1
    /\ UNCHANGED <<dhR, kemR, ct>>

Next ==
    \/ \E d \in {db, de}, k \in {ka, ke}, c \in {ctAB, cte} : Tamper(d, k, c)
    \/ Run

Spec == Init /\ [][Next]_vars

BoundedSteps == steps <= MaxSteps

\* P8a: an established session requires every half to be the honest one —
\* rewrite the DH pub, the KEM pub, or the ciphertext and the keys
\* diverge, the equality check fails, and the session stays failed.
P8EstablishedUntampered ==
    phaseI = "ESTABLISHED" /\ phaseR = "ESTABLISHED" =>
        /\ dhR = db /\ kemR = ka /\ ct = ctAB

\* P8b: established implies BOTH halves were mixed — the session key is
\* never a one-half key (no silent downgrade to DH-only or KEM-only).
P8BothHalvesMixed ==
    phaseI = "ESTABLISHED" => keyI = <<sab, sAB>>

Safety == P8EstablishedUntampered /\ P8BothHalvesMixed
====
