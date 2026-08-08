# 05 — L3 Threat Intelligence: Detailed Specification

L3 makes the network *smarter*: it pools per-org detection signals
(L0 watchdogs, L2-verified claims, L4 reputation) into cross-org
correlation and feeds signed risk advice back to orgs — without ever
learning an org's raw data (differential privacy) and without a single
aggregator being able to link signal to org (secure aggregation). The
output is the `RISK_FEED`: a per-org risk vector plus recommended
actions, every entry backed by `cert_refs` (attributable evidence). This
document is the normative L3 design: formal privacy, system model,
algorithms with pseudocode, protocol flows, evaluation, and the labeled
dataset story.

---

## 1. Problem statement (formal)

**Informal.** An org is attacked. Its L0 watchdogs fire. Alone, it
knows *something* happened. The network can know *more*: the same
fingerprint appearing in three orgs' logs in one week is an outbreak;
the same scope misconfiguration pattern across orgs is a systemic
vulnerability. But no org wants to share its logs, and no aggregator
should be trusted with them.

**Formal (DP for aggregate statistics).** Let `X_i` be org `i`'s
signal vector (per-epoch, per-signal: e.g., alarm counts by type). A
function `g` over orgs' data (e.g., global alarm-rate by type,
correlation between `fp` and incident outcomes) is computed with
differential privacy: `Pr[g(X) ∈ S] ≤ e^ε · Pr[g(X') ∈ S] + δ` for all
databases differing in one org's row, with `(ε, δ)` published and
audited. Every published aggregate carries its `(ε, δ)` budget in the
signed observation — an org can *verify* how much privacy it donated.

**Formal (secure aggregation).** The aggregator receives
`Enc(shares of X_i)` and, without decrypting, computes
`Σ X_i / n` — i.e., it learns the sum but never individual rows.
Bonawitz-style pairwise masks + a (short) MPC for final unmasking;
v1 uses a non-colluding pair of aggregators (honest-majority
assumption), documented and priced (L4).

**Research question.** Streaming CUSUM-style change detection over
*DP-noised, secure-aggregated* signals: what is the detection
latency/recall degradation as `ε` shrinks? At what `ε` does
cross-org detection stop being useful? (The paper's central plot.)

---

## 2. System model

- **Participants.** Org gateways (signal producers, L0), aggregation
  nodes (2 non-colluding, deployment `01 §6`), the correlation registry
  (L2-backed, authorized predicate queries only), consumers (orgs,
  L4).
- **Signals (v1 set, per org per epoch Δt = 1 h):**
  `alarm_counts[type]`, `import_count`, `reject_count`,
  `key_rotations`, `avg_key_age`, `watchdog_detected_bools`,
  `stale_sth_seconds`, `scp_failures`.
- **Labeled target:** per-org per-epoch *incident flag* `y_i(t)` —
  ground truth defined by *verified* compromise (council-verified
  events, i.e., L0's `COMPROMISE_DETECTED` events are the positive
  class). The dataset generator (`bench.go` S1–S7 scenarios) emits
  both signals and ground-truth labels, so every model is trained and
  evaluated on labeled data.
- **Assumptions.** Honest-majority between the two aggregators; orgs
  are rational (L4 prices honesty); a corrupted org's *own* data may be
  poisoned (defense in §5).

---

## 3. Privacy architecture (normative)

```
org_i  →  [secure aggregation]  →  global stats (DP)  →  published
  |____________________________________|
  (raw signals never leave the org; even the aggregators never see them)
```

- **Layer 1 — secure aggregation** (hides *which* org contributed what).
- **Layer 2 — DP** (hides whether a single org's row changed the
  aggregate; protects against membership inference by the *audience*
  of the published stats).
- **Layer 3 — per-org noise accounting.** Each org's contribution is
  a signed observation carrying its own budget counter (`eps_used`,
  `delta_used`); a global budget per epoch is enforced by the
  aggregator; budget exhaustion → org must wait or accept lower
  precision (mechanism: Laplace/ Gaussian noise scaled by budget).

**Why both layers.** Secure aggregation alone protects against the
aggregator, but not against a *colluding subset* of orgs reconstructing
others' rows from aggregate differences; DP alone protects against
difference attacks but not against a malicious aggregator that simply
doesn't add noise. Neither is sufficient alone; the composition
(Bonawitz + DP) is the defense we ship and the *ablation* (both,
each alone, neither) is a paper experiment.

---

## 4. Core algorithms (normative)

### 4.1 Secure aggregation (Bonawitz et al., 2017 — adopted)

```
for epoch t:
  orgs agree on masking vector set (pairwise seeds)
  each org: y_share = X_i + Σ_{j} mask(i,j)
  send to aggregator A (B holds seeds)
  A receives all y_shares; B reveals masks per-org
  → sum = Σ y_shares − Σ masks   (no single aggregator sees X_i)
  → aggregate = sum / n; add DP noise (Layer 2)
```

v1 simplification (documented): two non-colluding aggregators, honest
majority, no malicious-aggregator recovery; upgrade path: full MPC
with the L1 cluster as the MPC committee (a *research* target — see
`03 §6` cross-org FROST reuse).

### 4.2 Change detection: streaming CUSUM on noised aggregates

Per signal `s`: maintain `C_s(t) = max(0, C_s(t−1) + Δ_s(t) − k)`
where `Δ_s(t)` is the epoch-over-epoch residual and `k` the drift
allowance. Alarm when `C_s(t) > h_s` (threshold). **DP interaction:**
noise inflates variance; `h_s` and `k` must be chosen from the noise
distribution — derive `(k, h)` from the *noised* distribution so the
false-positive rate stays at target despite noise (the central
research plot: ROC curves at ε ∈ {0.1, 0.5, 1.0, 5.0, ∞}).

### 4.3 Correlation and recommendation

```
on cross-org pattern match (e.g., same fp in ≥ 3 orgs within 7d):
  weight edges via L4 reputation (patterns among trusted orgs weigh more)
  emit RISK_FEED for each affected org:
    { org, risk_vector[t..t+24h], recommended_actions[],
      confidence, cert_refs[] }   (signed, L3 aggregate key)
```

Recommendations are *suggestions*: L0's proactive-rotation gate
(`01 §7.4`) verifies signature + refs and applies org-local policy.
L3 never bypasses L0's decision authority.

---

## 5. Attack model and defenses

| Attack | Defense |
|---|---|
| Malicious aggregator (single) | non-colluding pair; corruption detectable by cross-checking signed aggregates |
| Malicious aggregator pair | L1-MPC upgrade (documented ceiling; `// ponytail: two-aggregator honest majority`) |
| Poisoning: org reports fake signals | L4 reputation discounts; outlier-robust aggregation (trimmed mean over certified orgs) |
| Membership inference from stats | DP per aggregate; budget accounting per org |
| Difference attacks (colluding orgs) | DP (the noise, not the masking, is the defense) |
| Sybil signal farms | L4 enrollment cost (§`06 §4`); certified-org filtering before aggregation |

---

## 6. The labeled dataset (normative artifact)

`bench.go` S1–S7 scenarios generate full *incident timelines*: benign
periods, single-org compromise, key-theft with lateral move, import
abuse, council-abuse, ransomware-style mass rotation, and background
noise. Each scenario produces: (a) per-org signal streams; (b)
ground-truth incident intervals; (c) the signed observation stream
that L3 would consume. **Dataset policy** (in the paper): generator
public, seed pinned, per-epoch releases versioned; models are trained
on S1–S6, tested on S7 (held-out scenario) — the honest out-of-sample
split that avoids scenario-overfitting.

**Evaluation metrics:** detection precision/recall, mean-detection
latency, false-positive rate at target ε, per-org privacy budget
consumption, degradation curve `metric(ε)`.

---

## 7. Interfaces

- **In:** signed observations (`STH`, `ALERT`, `ROTATION`, `SCORE`,
  registry predicate results from L2), L4 reputation vector.
- **Out:** signed `RISK_FEED` observations (orgs, L4), published global
  stats (public, with ε budget), detection events (public, alarmable
  by witnesses).
- **To L5:** the DP proof obligations (below) and the generator
  artifacts.

---

## 8. Research sub-problems (expanded)

1. **DP-noise-aware CUSUM tuning** — the main paper result; needs the
   noised-distribution derivation (§4.2).
2. **Composition accounting across layers** — DP budget spent by
   aggregates *and* by L2 predicate answers must compose (advanced
   composition theorem); the registry (L2) is the shared budget
   ledger.
3. **Privacy-preserving correlation** — correlate across orgs on the
   *fingerprint* axis without leaking which orgs matched: answer
   "k orgs saw fp" with `COUNT_OF` style proof (L2 §4.3), never "which".
4. **Robust aggregation under sybil** — certified-org filtering + L4
   weights as the poisoning defense (ablation in paper).
5. **Threshold alarms as verifiable claims** — an alarm is a claim
   provable from `cert_refs` (L5 target: alarm ⇒ evidence).

---

## 9. Milestones and deliverables

| Milestone | Content | Artifact |
|---|---|---|
| M1 (mo 1–3) | Secure aggregation + DP pipeline; budget accounting; noise-aware CUSUM | pipeline + benchmark (ε-sweep tables) |
| M2 (mo 4–5) | Correlation + RISK_FEED + proactive-rotation gate; poisoning defenses | end-to-end demo on generated scenarios |
| M3 (mo 6–8) | Dataset freeze (S1–S7), model eval, held-out scenario, ROC/ε curves | dataset + eval artifact |
| M4 (mo 9–12) | Write-up + artifact freeze | paper draft (CCS / NDSS / S&P) |

**Related work (deep).** Federated learning (McMahan et al., 2017) —
the standard FL frame; we are FL's *monitoring* cousin: federated
aggregates of detection signals, no model training across orgs (v1).
Secure aggregation (Bonawitz et al., 2017) — adopted wholesale. DP-SGD
(Abadi et al., 2016) — the per-example budget accounting analogy.
Threat-intel sharing (MISP, STIX/TAXII) — the *operational* baseline:
MISP shares raw indicators, which leaks; we share *aggregates with
proofs*. Correlation engines (IBM QRadar, Splunk ES) — single-org
horizon; we are cross-org by construction. The novelty: *provable
privacy budget alongside actionable cross-org intelligence, on top of
verifiable L0 evidence*.
