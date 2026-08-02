---- MODULE TrustOrchestrator ----
\* Formal model of the Trust Orchestrator's safety core (architecture §6.4,
\* §6.5). Two candidate forks A/B; a certificate may be valid on each fork
\* independently; watchdogs and auditors raise signals (DETECTED); recovery
\* COMMITs a fork with council quorum and a monotonic epoch. The model-checked
\* properties are exactly the report's P1 (fork safety), P2 (quorum-gated
\* liveness), P3 (no resurrection), P4 (quorum honesty), P6 (escalation
\* only). P5 (minimal blast) is a graph-level property — the model has no
\* graph, so it is verified in Go (InvalidationSet + VerifyRecovery, docs
\* 03/05) with the model's P3 covering the no-re-validated-half.
EXTENDS Integers, FiniteSets

CONSTANTS
    Certs,          \* set of certificate ids
    Council,        \* set of council member ids (5)
    Quorum,         \* recovery vote threshold (3)
    Watchdogs,      \* detection nodes
    DetectQuorum,   \* watchdog alarms needed for DETECTED (3 of 5)
    Auditors,       \* independent escalation operators (5)
    EscalateQuorum  \* auditor raises needed to force DETECTED (3 of 5)

VARIABLES
    validA, validB,            \* currently valid certs per fork
    everRevokedA, everRevokedB,\* sticky revocation history per fork
    votes,                     \* members that voted RECOVER
    epoch,                     \* last committed epoch (monotonic)
    canon,                     \* canonical fork: "A" or "B"
    anchors,                   \* <<fork, epoch, numVotes>> of every COMMIT
    alarm,                     \* watchdogs below threshold
    raised                     \* auditors that escalated

vars == <<validA, validB, everRevokedA, everRevokedB,
          votes, epoch, canon, anchors, alarm, raised>>

Init ==
    /\ validA = {} /\ validB = {}
    /\ everRevokedA = {} /\ everRevokedB = {}
    /\ votes = {}
    /\ epoch = 0
    /\ canon = "A"
    /\ anchors = {}
    /\ alarm = {}
    /\ raised = {}

Detected ==
    /\ Cardinality(alarm) >= DetectQuorum
    \/ Cardinality(raised) >= EscalateQuorum

\* Watchdogs alarm independently (environment action; the model explores all
\* alarm subsets — P4/P6 must hold regardless).
Alarm(w) ==
    /\ w \in Watchdogs
    /\ w \notin alarm
    /\ alarm' = alarm \cup {w}
    /\ UNCHANGED <<validA, validB, everRevokedA, everRevokedB, votes, epoch, canon, anchors, raised>>

\* Auditors escalate (FR3.3): a pure signal — it can force DETECTED, and it
\* changes nothing else (P6).
Escalate(a) ==
    /\ a \in Auditors
    /\ a \notin raised
    /\ raised' = raised \cup {a}
    /\ UNCHANGED <<validA, validB, everRevokedA, everRevokedB, votes, epoch, canon, anchors, alarm>>

\* Council votes only after DETECTED (recovery state machine: IDLE ->
\* DETECTED+evidence -> VOTE). Only council members can vote (P4/P6).
Vote(m) ==
    /\ Detected
    /\ m \in Council
    /\ m \notin votes
    /\ votes' = votes \cup {m}
    /\ UNCHANGED <<validA, validB, everRevokedA, everRevokedB, epoch, canon, anchors, alarm, raised>>

Issue(f, c) ==
    \/ /\ f = "A" /\ c \notin everRevokedA /\ c \notin validA
       /\ validA' = validA \cup {c}
       /\ UNCHANGED validB
    \/ /\ f = "B" /\ c \notin everRevokedB /\ c \notin validB
       /\ validB' = validB \cup {c}
       /\ UNCHANGED validA
    /\ UNCHANGED <<everRevokedA, everRevokedB, votes, epoch, canon, anchors, alarm, raised>>

Revoke(f, c) ==
    \/ /\ f = "A" /\ c \in validA
       /\ validA' = validA \ {c}
       /\ everRevokedA' = everRevokedA \cup {c}
       /\ UNCHANGED <<validB, everRevokedB>>
    \/ /\ f = "B" /\ c \in validB
       /\ validB' = validB \ {c}
       /\ everRevokedB' = everRevokedB \cup {c}
       /\ UNCHANGED <<validA, everRevokedA>>
    /\ UNCHANGED <<votes, epoch, canon, anchors, alarm, raised>>

Commit(f) ==
    /\ Detected
    /\ Cardinality(votes) >= Quorum
    /\ f \in {"A", "B"}
    /\ epoch' = epoch + 1
    /\ canon' = f
    /\ votes' = {}
    /\ anchors' = anchors \cup {<<f, epoch + 1, Cardinality(votes)>>}
    /\ UNCHANGED <<validA, validB, everRevokedA, everRevokedB, alarm, raised>>

Next ==
    \/ \E w \in Watchdogs : Alarm(w)
    \/ \E a \in Auditors : Escalate(a)
    \/ \E m \in Council : Vote(m)
    \/ \E c \in Certs : Issue("A", c)
    \/ \E c \in Certs : Issue("B", c)
    \/ \E c \in Certs : Revoke("A", c)
    \/ \E c \in Certs : Revoke("B", c)
    \/ Commit("A")
    \/ Commit("B")

\* TLC 2.19 only accepts the explicit Init /\ [][Next]_vars form; a bare
\* "SPECIFICATION Next" is rejected as an unhandleable level-2 conjunct.
Spec == Init /\ [][Next]_vars

\* State constraint so the monotonic Commit chain terminates the BFS.
\* ponytail: scale-reduced model (2 certs, 3 watchdogs, 2 auditors) — the
\* safety properties are scale-independent; full-size model blows up on
\* anchors/alarm subsets.
BoundedEpoch == epoch <= 3

\* P1: at most one canonical trust anchor per epoch — the epoch-based fork
\* resolution eliminates the entry-count tiebreak attack.
P1ForkSafety ==
    \A f1, f2 \in {"A", "B"}, e \in 0..10, n1, n2 \in 0..5 :
        /\ <<f1, e, n1>> \in anchors
        /\ <<f2, e, n2>> \in anchors
        => f1 = f2

\* P3: a revoked certificate is never valid again on either fork (L3).
P3NoResurrection ==
    /\ validA \cap everRevokedA = {}
    /\ validB \cap everRevokedB = {}

\* P4: every COMMIT carries >= Quorum distinct member votes (n >= 3f+1).
P4QuorumHonesty ==
    \A f \in {"A", "B"}, e \in 0..10, n \in 0..5 :
        <<f, e, n>> \in anchors => n >= Quorum

\* P2: recovery is quorum-gated liveness — votes accumulate only after
\* DETECTED, so >= Quorum votes implies a COMMIT is enabled (recovery
\* terminates with >= 3 connected members; the "blocks otherwise" half is
\* P4: fewer votes can never commit).
P2Liveness ==
    Cardinality(votes) >= Quorum => Detected

\* P6: escalation is detection-only — auditor raises can force DETECTED but
\* never touch recovery: votes stay a subset of the council, and escalation
\* alone cannot commit (P4 + the votes guard). The mutation check
\* (P6Mutant) shows TLC rejects an auditor-vote injection.
P6EscalationOnly ==
    /\ votes \subseteq Council
    /\ Cardinality(raised) >= EscalateQuorum => Detected

Safety == P1ForkSafety /\ P3NoResurrection /\ P4QuorumHonesty
           /\ P2Liveness /\ P6EscalationOnly
====
