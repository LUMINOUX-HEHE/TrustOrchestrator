package main

// to-auditor: independent audit of the transparency mirror (deployment
// guide §7: to-auditor audit --log <url> --policy policy.yaml). The log is
// a timeline dump; the policy is the operator-declared conformance surface
// (FR3.2). Auditors can escalate detection, never execute recovery (P6).

import (
	"encoding/json"
	"fmt"
	"os"

	to "trustorchestrator"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "audit" {
		usage()
	}
	logPath, policyPath := "", ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--log":
			if i+1 < len(args) {
				logPath = args[i+1]
				i++
			}
		case "--policy":
			if i+1 < len(args) {
				policyPath = args[i+1]
				i++
			}
		}
	}
	if logPath == "" || policyPath == "" {
		usage()
	}
	if err := audit(logPath, policyPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  to-auditor audit --log <file> --policy <file>
    <file>: timeline dump to audit (auditor's mirror)
    <file>: policy JSON, {"max_issues_per_identity_per_window": K}`)
	os.Exit(1)
}

func audit(logPath, policyPath string) error {
	tl, err := to.LoadTimeline(logPath)
	if err != nil {
		return err
	}
	polRaw, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	var pol to.Policy
	if err := json.Unmarshal(polRaw, &pol); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	// 1. Chain integrity (FR3.2): the auditor holds the verification key.
	bad := tl.LocateBadEvent()
	if bad >= 0 {
		fmt.Printf("CHAIN: FAIL (broken at event #%d)\n", bad)
	} else {
		fmt.Printf("CHAIN: PASS (root %x)\n", tl.Head())
	}
	// 2. Policy conformance (FR3.2).
	violations := to.CheckPolicy(tl.Events(), pol)
	if len(violations) == 0 {
		fmt.Println("POLICY: PASS")
	} else {
		fmt.Println("POLICY: FAIL")
		for _, v := range violations {
			fmt.Printf("  violation: %s\n", v)
		}
		// 3. Escalation signal (FR3.3): auditors can raise, not execute.
		fmt.Println("ESCALATE: recommend (>=3 auditor operators agree in deployment)")
	}
	return nil
}
