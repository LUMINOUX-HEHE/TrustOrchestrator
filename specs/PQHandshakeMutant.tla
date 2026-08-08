---- MODULE PQHandshakeMutant ----
\* MUTATION TEST for P8 (test plan §3): the hybrid mix drops the KEM
\* half (mix is the identity on the DH half). Expected outcome: TLC
\* reports "Invariant Safety is violated" — proving the established-
\* session invariant requires BOTH halves of the hybrid handshake.
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    MaxSteps

VARIABLES
    dhR, kemR, ct, keyI, keyR, phaseI, phaseR, steps

vars == <<dhR, kemR, ct, keyI, keyR, phaseI, phaseR, steps>>

NULL == "NULL"
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

dh(p, q) ==
    IF {p, q} = {da, db} THEN sab
    ELSE IF {p, q} = {da, de} THEN sae
    ELSE NULL

KEMENC(k) == IF k = ka THEN sAB ELSE IF k = ke THEN sE ELSE NULL
KEMDEC(priv, c) == IF priv = kb /\ c = ctAB THEN sAB ELSE NULL

\* MUTANT: the mix uses only the DH half — the KEM half is discarded, so
\* a tampered ciphertext (or KEM key) can no longer block the session.
mix(a, b) == a

Init ==
    /\ dhR = db /\ kemR = ka /\ ct = ctAB
    /\ keyI = NULL /\ keyR = NULL
    /\ phaseI = "IDLE" /\ phaseR = "IDLE"
    /\ steps = 0

Tamper(d, k, c) ==
    /\ d \in {db, de} /\ k \in {ka, ke} /\ c \in {ctAB, cte}
    /\ dhR' = d /\ kemR' = k /\ ct' = c
    /\ keyI' = NULL /\ keyR' = NULL
    /\ phaseI' = "IDLE" /\ phaseR' = "IDLE"
    /\ steps' = steps

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

P8EstablishedUntampered ==
    phaseI = "ESTABLISHED" /\ phaseR = "ESTABLISHED" =>
        /\ dhR = db /\ kemR = ka /\ ct = ctAB

P8BothHalvesMixed ==
    phaseI = "ESTABLISHED" => keyI = <<sab, sAB>>

Safety == P8EstablishedUntampered /\ P8BothHalvesMixed
====
