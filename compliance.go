package trustorchestrator

// compliance.go — evidence-based compliance reports (ISO 27001, SOC 2,
// PCI DSS, HIPAA, GDPR). Status is derived only from what the deployment
// actually proves: pass = automated evidence in hand, manual = operator
// attestation (the note says what to provide), missing = no evidence found.
// The report is the evidence trail an auditor asks for — the signed chain,
// the audit ring, RBAC, at-rest crypto, backup — not a certification.
// ponytail: static control table per framework; extend the table when a
// real audit asks for a control this deployment can prove.

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ControlStatus is one control's verdict.
type ControlStatus string

const (
	StatusPass    ControlStatus = "pass"    // automated evidence present
	StatusManual  ControlStatus = "manual"  // operator attestation required
	StatusMissing ControlStatus = "missing" // no evidence found
)

// ControlResult is one framework control and its verdict.
type ControlResult struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Status   ControlStatus `json:"status"`
	Evidence []string      `json:"evidence"`
	Note     string        `json:"note,omitempty"`
}

// FrameworkReport is one framework's control results with a status tally.
type FrameworkReport struct {
	Name     string          `json:"name"`
	Controls []ControlResult `json:"controls"`
	Pass     int             `json:"pass"`
	Manual   int             `json:"manual"`
	Missing  int             `json:"missing"`
}

// ComplianceReport is the full generated report.
type ComplianceReport struct {
	Generated  time.Time         `json:"generated"`
	Evidence   ComplianceSummary `json:"evidence"`
	Frameworks []FrameworkReport `json:"frameworks"`
	Findings   []string          `json:"findings"`
}

// ComplianceSummary is the auditable facts the report is built from —
// machine-readable so the same report can feed dashboards or later
// attestation tooling.
type ComplianceSummary struct {
	TimelineEvents   int      `json:"timeline_events"`
	TimelineValid    bool     `json:"timeline_valid"`
	CouncilAnchor    bool     `json:"council_anchor"`
	Detections       int      `json:"detections"`
	Recoveries       int      `json:"recoveries"`
	Revocations      int      `json:"revocations"`
	AuditEntries     int      `json:"audit_entries"`
	Users            int      `json:"users"`
	Roles            []string `json:"roles"`
	HasBackup        bool     `json:"has_backup"`
	HasVault         bool     `json:"has_vault"`
	Webhooks         int      `json:"webhooks"`
	PolicyViolations []string `json:"policy_violations,omitempty"`
}

// ComplianceEvidence is what the report evaluates. The CLI collects it
// from operator files (cmd/orchestrator report); tests build it directly.
type ComplianceEvidence struct {
	Timeline     *Timeline
	AuditEntries []AuditEntry
	Users        map[string]string // id -> role; nil = no gateway info
	Webhooks     int
	HasBackup    bool
	HasVault     bool // gateway.keys (envelope-encrypted at rest) present
	Policy       Policy
}

// BuildComplianceReport derives the statuses and findings from the evidence.
func BuildComplianceReport(ev *ComplianceEvidence) *ComplianceReport {
	facts := computeFacts(ev)
	r := &ComplianceReport{Generated: time.Now().UTC(), Evidence: facts}
	for _, f := range buildFrameworks(facts) {
		r.Frameworks = append(r.Frameworks, f)
	}
	if !facts.TimelineValid && facts.TimelineEvents > 0 {
		r.Findings = append(r.Findings, "TIMELINE FAILS VERIFICATION — do not submit this report")
	}
	if facts.Users == 0 {
		r.Findings = append(r.Findings, "no gateway users defined — RBAC not configured")
	}
	if facts.AuditEntries == 0 {
		r.Findings = append(r.Findings, "no action audit entries — export /v1/audit?source=actions")
	}
	if !facts.HasBackup {
		r.Findings = append(r.Findings, "no backup artifact — A.8.13 / SOC 2 A1.2 / HIPAA 164.308(a)(1)(ii)(B) evidence missing")
	}
	if !facts.HasVault {
		r.Findings = append(r.Findings, "no at-rest encryption evidence (gateway.keys / vault envelope)")
	}
	for _, v := range facts.PolicyViolations {
		r.Findings = append(r.Findings, "POLICY VIOLATION: "+v)
	}
	return r
}

func computeFacts(ev *ComplianceEvidence) ComplianceSummary {
	var s ComplianceSummary
	if ev.Timeline != nil {
		s.TimelineEvents = len(ev.Timeline.Events())
		s.TimelineValid = ev.Timeline.Verify()
		s.CouncilAnchor = len(ev.Timeline.CouncilPub()) == ed25519.PublicKeySize
		for _, e := range ev.Timeline.Events() {
			switch e.Type {
			case EvDetected:
				s.Detections++
			case EvRecovery:
				s.Recoveries++
			case EvRevoke:
				s.Revocations++
			}
		}
	}
	s.AuditEntries = len(ev.AuditEntries)
	s.Users = len(ev.Users)
	seen := map[string]bool{}
	for _, role := range ev.Users {
		if !seen[role] {
			seen[role] = true
			s.Roles = append(s.Roles, role)
		}
	}
	sort.Strings(s.Roles)
	s.HasBackup = ev.HasBackup
	s.HasVault = ev.HasVault
	s.Webhooks = ev.Webhooks
	if ev.Policy.MaxIssuesPerIdentityPerWindow > 0 && ev.Timeline != nil {
		s.PolicyViolations = CheckPolicy(ev.Timeline.Events(), ev.Policy)
	}
	return s
}

// ---- control verdicts (shared across frameworks) ----

func pass(evidence ...string) ControlResult {
	return ControlResult{Status: StatusPass, Evidence: evidence}
}

func manual(note string) ControlResult { return ControlResult{Status: StatusManual, Note: note} }

func missing() ControlResult { return ControlResult{Status: StatusMissing} }

// manualStatic wraps a fixed-manual control (attestation-only rows) as a
// verdict function.
func manualStatic(note string) func(ComplianceSummary) ControlResult {
	return func(ComplianceSummary) ControlResult { return manual(note) }
}

func rbacStatus(s ComplianceSummary) ControlResult {
	if s.Users == 0 {
		return missing()
	}
	if len(s.Roles) >= 2 {
		return pass(fmt.Sprintf("role-based access: %s", strings.Join(s.Roles, ", ")))
	}
	return manual("single role present — attest least-privilege mapping")
}

func authStatus(s ComplianceSummary) ControlResult {
	if s.Users == 0 {
		return missing()
	}
	return pass("bearer-token auth; tokens stored as SHA-256; per-token org scoping")
}

func adminStatus(s ComplianceSummary) ControlResult {
	for _, r := range s.Roles {
		if r == RoleAdmin {
			return pass("privileged role separated (admin)")
		}
	}
	return missing()
}

func logStatus(s ComplianceSummary) ControlResult {
	if s.TimelineValid && s.TimelineEvents > 0 {
		return pass(fmt.Sprintf("append-only signed hash chain, %d events, verification PASS", s.TimelineEvents))
	}
	if s.TimelineEvents > 0 {
		return ControlResult{Status: StatusMissing, Note: "timeline failed chain verification"}
	}
	return missing()
}

func monitorStatus(s ComplianceSummary) ControlResult {
	if s.Detections > 0 {
		return pass(fmt.Sprintf("%d DETECTED events from the watchdog ensemble (3/5 fusion)", s.Detections))
	}
	return manual("no detection evidence — run bench S1-S7 or a live watchdog fleet")
}

func backupStatus(s ComplianceSummary) ControlResult {
	if s.HasBackup {
		return pass("backup artifact present (snapshot bundle / data dir copy)")
	}
	return missing()
}

func cryptoStatus(s ComplianceSummary) ControlResult {
	if s.HasVault {
		return pass("envelope encryption: KEK in 3-of-5 council shares, DEK, per-epoch HKDF subkeys")
	}
	return manual("no vault evidence — attest seal key (gateway.key) or envelope at-rest policy")
}

func incidentStatus(s ComplianceSummary) ControlResult {
	if s.Recoveries > 0 && s.CouncilAnchor {
		return pass(fmt.Sprintf("%d recoveries threshold-signed by the FROST council", s.Recoveries))
	}
	if s.Recoveries > 0 {
		return manual("recoveries on record — attest the response playbook")
	}
	return missing()
}

func changeStatus(s ComplianceSummary) ControlResult {
	if s.TimelineValid && s.TimelineEvents > 0 {
		return pass("every change is a signed chain event: ISSUE/REVOKE/POLICY_CHANGE/RECOVERY")
	}
	return missing()
}

func recordStatus(s ComplianceSummary) ControlResult {
	if s.AuditEntries > 0 {
		return pass(fmt.Sprintf("%d gateway action entries (who/what/when)", s.AuditEntries))
	}
	if s.TimelineEvents > 0 {
		return manual("timeline is signed but no action audit provided — export /v1/audit?source=actions")
	}
	return missing()
}

// ---- framework tables ----

type controlDef struct {
	id, title string
	fn        func(ComplianceSummary) ControlResult
}

func buildFrameworks(s ComplianceSummary) []FrameworkReport {
	table := []struct {
		name string
		defs []controlDef
	}{
		{"ISO 27001:2022", []controlDef{
			{"A.5.15", "Access control", rbacStatus},
			{"A.5.17", "Authentication information", authStatus},
			{"A.8.2", "Privileged access rights", adminStatus},
			{"A.8.11", "Logging", logStatus},
			{"A.8.12", "Monitoring", monitorStatus},
			{"A.8.13", "Information backup", backupStatus},
			{"A.8.24", "Use of cryptography", cryptoStatus},
		}},
		{"SOC 2", []controlDef{
			{"CC6.1", "Restrict logical access", rbacStatus},
			{"CC6.2", "User provisioning and de-provisioning", func(s ComplianceSummary) ControlResult {
				if s.Users > 0 && s.AuditEntries > 0 {
					return pass("user lifecycle recorded in the action audit")
				}
				return manual("attest provisioning/de-provisioning procedure and its audit trail")
			}},
			{"CC6.3", "Role-based access", func(s ComplianceSummary) ControlResult {
				if len(s.Roles) >= 2 {
					return pass(fmt.Sprintf("distinct roles: %s", strings.Join(s.Roles, ", ")))
				}
				return missing()
			}},
			{"CC6.6", "Logical access security", authStatus},
			{"CC7.2", "Anomaly detection", monitorStatus},
			{"CC7.3", "Incident response", incidentStatus},
			{"CC8.1", "Change management", changeStatus},
			{"A1.2", "Recovery", func(s ComplianceSummary) ControlResult {
				if s.HasBackup && s.Recoveries > 0 {
					return pass(fmt.Sprintf("%d recoveries on record; backup artifact present", s.Recoveries))
				}
				if s.HasBackup || s.Recoveries > 0 {
					return manual("backup or recovery evidence is partial — attest the full cycle")
				}
				return missing()
			}},
		}},
		{"PCI DSS 4.0", []controlDef{
			{"Req 7", "Restrict access to system components", rbacStatus},
			{"Req 8", "Identify users and authenticate access", authStatus},
			{"Req 3", "Protect stored account data", cryptoStatus},
			{"Req 4", "Protect transmissions", manualStatic("mTLS TLS 1.3 on the fleet/council wire; attest key rotation policy")},
			{"Req 10", "Log and monitor all access", logStatus},
			{"Req 11", "Test security regularly", manualStatic("evidence: bench S1-S7, kill suite K1-K6, TLA+ model check, fuzz targets")},
			{"Req 12", "Support information security", manualStatic("incident response plan, roles and risk assessment")},
		}},
		{"HIPAA", []controlDef{
			{"164.312(a)", "Access control", rbacStatus},
			{"164.312(b)", "Audit controls", recordStatus},
			{"164.312(c)", "Integrity", func(s ComplianceSummary) ControlResult {
				if s.TimelineValid && s.TimelineEvents > 0 {
					return pass("signed hash chain detects tampering; verification PASS")
				}
				return missing()
			}},
			{"164.312(e)", "Transmission security", manualStatic("mTLS TLS 1.3 on the fleet/council wire")},
			{"164.308(a)(1)(ii)(B)", "Contingency plan (backup)", backupStatus},
		}},
		{"GDPR", []controlDef{
			{"Art. 25", "Data protection by design", manualStatic("minimal blast-radius re-issuance (P5); encryption at rest by default")},
			{"Art. 30", "Records of processing", recordStatus},
			{"Art. 32", "Security of processing", func(s ComplianceSummary) ControlResult {
				if s.TimelineValid && s.HasVault {
					return pass("signed chain + envelope encryption at rest")
				}
				return manual("chain or at-rest encryption evidence incomplete")
			}},
			{"Art. 33/34", "Breach notification", func(s ComplianceSummary) ControlResult {
				if s.Webhooks > 0 {
					return pass(fmt.Sprintf("%d webhook endpoint(s) on detected/recovery events", s.Webhooks))
				}
				return manual("register notification endpoints (webhooks) and attest the notification procedure")
			}},
		}},
	}
	var out []FrameworkReport
	for _, f := range table {
		fr := FrameworkReport{Name: f.name}
		for _, d := range f.defs {
			r := d.fn(s)
			r.ID, r.Title = d.id, d.title
			fr.Controls = append(fr.Controls, r)
			switch r.Status {
			case StatusPass:
				fr.Pass++
			case StatusManual:
				fr.Manual++
			case StatusMissing:
				fr.Missing++
			}
		}
		out = append(out, fr)
	}
	return out
}
