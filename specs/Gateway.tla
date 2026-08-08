---- MODULE Gateway ----
\* Formal model of the gateway's fork-adoption gate (api.go handleRecover).
\* The core model (TrustOrchestrator.tla) proves P1-P6 at the engine level;
\* this module proves the API surface that LETS a fork into the org:
\*
\*   Adopt(fork, votes, idx, forkEpoch)  -- the exact guard set of
\*   POST /v1/orgs/{org}/recover:
\*     1. handoff present at position idx (0 <= idx <= Len(fork))
\*     2. the handoff carries >= Quorum distinct council signatures
\*     3. forkEpoch strictly greater than the org's current epoch
\*        (no replay of a stale recovery)
\*     4. the fork descends from THIS org's verified prefix: events
\*        before the handoff are hash-for-hash equal to the org chain's
\*        (fork[1..idx] = orgChain[1..idx], idx <= Len(orgChain))
\*
\* The attacker (environment) proposes arbitrary forks; TLC explores every
\* combination. P7 = the gate never lets a fork through that violates
\* quorum, prefix descent, or epoch monotonicity. Prefix descent is the
\* gateway-level P3: revocations live in the prefix, so a fork can only
\* ever remove events past a council-signed handoff — history (including
\* revocations) up to the handoff is preserved. Mutation test
\* (GatewayP7Mutant, drop of check 4) shows TLC rejects the weakened gate.
\*
\* ponytail: scale-reduced model (2 hashes, chains of length <= 2, 2
\* epochs) — the properties are scale-independent, and the full domain
\* blows up the adoptions log. Each adoption record carries the fork
\* itself (no pre-snapshot: the org chain at adoption i is always the
\* fork adopted at i-1, or empty for the genesis adoption).
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    Hashes,   \* abstract event hashes (h1, h2)
    Quorum,   \* council signature threshold for a handoff
    MaxLen,   \* longest chain TLC explores
    MaxEpoch  \* largest handoff epoch TLC explores

VARIABLES
    orgChain,    \* sequence of hashes: the org's verified chain
    epoch,       \* last handoff epoch on the org chain (Go: lastEpoch)
    adoptions    \* sequence of <<forkEpoch, votes, idx, fork>> records

vars == <<orgChain, epoch, adoptions>>

Init ==
    /\ orgChain = <<>>
    /\ epoch = 0
    /\ adoptions = <<>>

\* Go's prefix loop: fork[1..idx] must equal pre's [1..idx], and idx must
\* not exceed pre's length (len(cur) < idx reject). idx = 0 is the
\* genesis handoff (empty prefix, always matches).
MatchesPrefix(fork, pre, idx) ==
    /\ idx <= Len(pre)
    /\ \A k \in 1..idx : fork[k] = pre[k]

Adopt(fork, votes, idx, forkEpoch) ==
    /\ idx >= 0 /\ idx <= Len(fork)
    /\ votes >= Quorum
    /\ forkEpoch > epoch
    /\ MatchesPrefix(fork, orgChain, idx)
    /\ orgChain' = fork
    /\ epoch' = forkEpoch
    /\ adoptions' = adoptions \o <<<<forkEpoch, votes, idx, fork>>>>

Next ==
    \E fork \in UNION { [1..n -> Hashes] : n \in 1..MaxLen },
       votes \in 0..Quorum,
       idx \in 0..MaxLen,
       forkEpoch \in 1..MaxEpoch :
        Adopt(fork, votes, idx, forkEpoch)

Spec == Init /\ [][Next]_vars

\* Epochs strictly increase per adoption, so the chain of adoptions is
\* bounded by MaxEpoch — this terminates the BFS.
BoundedEpoch == epoch <= MaxEpoch

\* P7a: no fork is ever adopted without >= Quorum council signatures.
P7QuorumSigned ==
    \A i \in 1..Len(adoptions) : adoptions[i][2] >= Quorum

\* P7b: every adopted fork descends from the chain that was current at
\* adoption: its events up to the handoff equal the previously adopted
\* fork's (the genesis adoption descends from the empty chain, so idx
\* must be 0). This is the gateway-level P3 — pre-handoff events,
\* including every revocation, survive adoption unchanged.
P7Descends ==
    \A i \in 1..Len(adoptions) :
        LET a == adoptions[i] IN
        IF i = 1 THEN a[3] = 0
        ELSE MatchesPrefix(a[4], adoptions[i - 1][4], a[3])

\* P7c: the org chain is always the last adopted fork (adoption is the
\* only mutation — the invariant pins the two variables together).
P7ChainCurrent ==
    orgChain = IF Len(adoptions) = 0 THEN <<>> ELSE adoptions[Len(adoptions)][4]

\* P7d: adopted handoffs advance the epoch monotonically — a stale
\* recovery is never replayed onto the org.
P7EpochMonotonic ==
    \A i \in 1..(Len(adoptions) - 1) : adoptions[i][1] < adoptions[i + 1][1]

Safety == P7QuorumSigned /\ P7Descends /\ P7ChainCurrent /\ P7EpochMonotonic
====
