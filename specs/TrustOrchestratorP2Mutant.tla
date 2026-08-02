---- MODULE TrustOrchestratorP2Mutant ----
\* MUTATION TEST for P2 (test plan §3): the council may vote before any
\* DETECTED signal (the Detected guard on Vote is removed). Expected
\* outcome: TLC reports "Invariant P2Liveness is violated" — proving the
\* guard is what makes recovery quorum-gated.
EXTENDS Integers, FiniteSets

CONSTANTS
    Certs, Council, Quorum, Watchdogs, DetectQuorum, Auditors, EscalateQuorum

VARIABLES
    validA, validB, everRevokedA, everRevokedB, votes, epoch, canon, anchors,
    alarm, raised

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

Alarm(w) ==
    /\ w \in Watchdogs
    /\ w \notin alarm
    /\ alarm' = alarm \cup {w}
    /\ UNCHANGED <<validA, validB, everRevokedA, everRevokedB, votes, epoch, canon, anchors, raised>>

Escalate(a) ==
    /\ a \in Auditors
    /\ a \notin raised
    /\ raised' = raised \cup {a}
    /\ UNCHANGED <<validA, validB, everRevokedA, everRevokedB, votes, epoch, canon, anchors, alarm>>

\* MUTANT: the Detected guard is removed — votes may accumulate with no
\* detection. P2Liveness must fail.
Vote(m) ==
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

Spec == Init /\ [][Next]_vars

BoundedEpoch == epoch <= 3

P1ForkSafety ==
    \A f1, f2 \in {"A", "B"}, e \in 0..10, n1, n2 \in 0..5 :
        /\ <<f1, e, n1>> \in anchors
        /\ <<f2, e, n2>> \in anchors
        => f1 = f2

P3NoResurrection ==
    /\ validA \cap everRevokedA = {}
    /\ validB \cap everRevokedB = {}

P4QuorumHonesty ==
    \A f \in {"A", "B"}, e \in 0..10, n \in 0..5 :
        <<f, e, n>> \in anchors => n >= Quorum

P2Liveness ==
    Cardinality(votes) >= Quorum => Detected

P6EscalationOnly ==
    /\ votes \subseteq Council
    /\ Cardinality(raised) >= EscalateQuorum => Detected

Safety == P1ForkSafety /\ P3NoResurrection /\ P4QuorumHonesty
           /\ P2Liveness /\ P6EscalationOnly
====
