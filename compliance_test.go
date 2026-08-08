package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestComplianceReportStatuses(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	for i := 0; i < 3; i++ {
		pl, _ := json.Marshal(issuePayload{CertID: string(rune('a' + i)), Identity: "user"})
		if _, err := tl.Append(EvIssue, pl, int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	pl, _ := json.Marshal(map[string]int{"bad_index": 2})
	if _, err := tl.Append(EvDetected, pl, 3); err != nil {
		t.Fatal(err)
	}
	pl, _ = json.Marshal(map[string]string{"cert_id": "b"})
	if _, err := tl.Append(EvRevoke, pl, 4); err != nil {
		t.Fatal(err)
	}
	ev := &ComplianceEvidence{
		Timeline:     tl,
		Users:        map[string]string{"admin": RoleAdmin, "ops": RoleOperator},
		AuditEntries: []AuditEntry{{User: "ops", Method: "POST", Path: "/v1/orgs/acme/issue", Status: 201}},
		HasBackup:    true,
		HasVault:     true,
		Webhooks:     1,
	}
	r := BuildComplianceReport(ev)
	if !r.Evidence.TimelineValid || r.Evidence.Detections != 1 || r.Evidence.Revocations != 1 {
		t.Fatalf("facts: %+v", r.Evidence)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("fully provisioned evidence must have no findings: %v", r.Findings)
	}
	iso := frameworkByName(r, "ISO 27001:2022")
	if iso.Pass < 4 || iso.Missing != 0 {
		t.Fatalf("ISO: %d pass, %d manual, %d missing", iso.Pass, iso.Manual, iso.Missing)
	}
	if got := controlStatus(iso, "A.8.11"); got != StatusPass {
		t.Fatalf("A.8.11 = %s, want pass", got)
	}
	if got := controlStatus(iso, "A.8.13"); got != StatusPass {
		t.Fatalf("A.8.13 = %s, want pass", got)
	}
	if got := controlStatus(frameworkByName(r, "GDPR"), "Art. 33/34"); got != StatusPass {
		t.Fatalf("Art. 33/34 = %s, want pass (webhooks)", got)
	}
	// negative variant: bare timeline only — controls go missing, findings appear.
	r2 := BuildComplianceReport(&ComplianceEvidence{Timeline: tl})
	iso2 := frameworkByName(r2, "ISO 27001:2022")
	if got := controlStatus(iso2, "A.8.13"); got != StatusMissing {
		t.Fatalf("A.8.13 without backup = %s, want missing", got)
	}
	if got := controlStatus(iso2, "A.5.15"); got != StatusMissing {
		t.Fatalf("A.5.15 without users = %s, want missing", got)
	}
	if len(r2.Findings) == 0 {
		t.Fatal("bare timeline must produce findings")
	}
	// policy violation becomes a finding.
	ev.Policy = Policy{MaxIssuesPerIdentityPerWindow: 2}
	r3 := BuildComplianceReport(ev)
	if len(r3.Findings) != 1 || r3.Findings[0] == "" {
		t.Fatalf("policy violation finding expected, got %v", r3.Findings)
	}
}

func frameworkByName(r *ComplianceReport, name string) FrameworkReport {
	for _, f := range r.Frameworks {
		if f.Name == name {
			return f
		}
	}
	return FrameworkReport{}
}

func controlStatus(f FrameworkReport, id string) ControlStatus {
	for _, c := range f.Controls {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}
