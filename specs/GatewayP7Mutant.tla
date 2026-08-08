---- MODULE GatewayP7Mutant ----
\* MUTATION TEST for P7 (test plan §3): the adoption gate drops the
\* prefix-descent check (Adopt has no MatchesPrefix guard). Expected
\* outcome: TLC reports "Invariant Safety is violated" — proving the
\* prefix check is what prevents a fork that does not descend from the
\* org's verified chain from being adopted (a resurrection vector).
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    Hashes, Quorum, MaxLen, MaxEpoch

VARIABLES
    orgChain, epoch, adoptions

vars == <<orgChain, epoch, adoptions>>

Init ==
    /\ orgChain = <<>>
    /\ epoch = 0
    /\ adoptions = <<>>

MatchesPrefix(fork, pre, idx) ==
    /\ idx <= Len(pre)
    /\ \A k \in 1..idx : fork[k] = pre[k]

\* MUTANT: no MatchesPrefix guard — a fork whose prefix diverges from the
\* org chain can be adopted, which resurrects revoked/removed history.
Adopt(fork, votes, idx, forkEpoch) ==
    /\ idx >= 0 /\ idx <= Len(fork)
    /\ votes >= Quorum
    /\ forkEpoch > epoch
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

BoundedEpoch == epoch <= MaxEpoch

P7QuorumSigned ==
    \A i \in 1..Len(adoptions) : adoptions[i][2] >= Quorum

P7Descends ==
    \A i \in 1..Len(adoptions) :
        LET a == adoptions[i] IN
        IF i = 1 THEN a[3] = 0
        ELSE MatchesPrefix(a[4], adoptions[i - 1][4], a[3])

P7ChainCurrent ==
    orgChain = IF Len(adoptions) = 0 THEN <<>> ELSE adoptions[Len(adoptions)][4]

P7EpochMonotonic ==
    \A i \in 1..(Len(adoptions) - 1) : adoptions[i][1] < adoptions[i + 1][1]

Safety == P7QuorumSigned /\ P7Descends /\ P7ChainCurrent /\ P7EpochMonotonic
====
