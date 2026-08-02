// to-pdp: the policy decision point consumer (architecture §5.8, guide §3).
// Evaluates the operator-declared policy file against the trust timeline —
// the allow/deny reference the VPN/DNS consumers would query.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	to "trustorchestrator"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		usage()
	}
	if args[0] != "check" {
		usage()
	}
	if err := check(args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  to-pdp check --policy <policy.json> --events <timeline.json>`)
	os.Exit(1)
}

// check: load the policy + timeline, and answer per-identity allow/deny with
// the violations (FR3.2). Policy reload semantics: re-reading the policy file
// re-decides immediately — no restart, no daemon state.
func check(args []string) error {
	polPath, eventsFile := "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			if i+1 < len(args) {
				polPath = args[i+1]
				i++
			}
		case "--events":
			if i+1 < len(args) {
				eventsFile = args[i+1]
				i++
			}
		}
	}
	if polPath == "" || eventsFile == "" {
		return errors.New("usage: check --policy <policy.json> --events <timeline.json>")
	}
	raw, err := os.ReadFile(polPath)
	if err != nil {
		return err
	}
	var pol to.Policy
	if err := json.Unmarshal(raw, &pol); err != nil {
		return err
	}
	tl, err := load(eventsFile)
	if err != nil {
		return err
	}
	perID := map[string]int{}
	for _, e := range tl.Events() {
		if e.Type != to.EvIssue {
			continue
		}
		var p struct {
			Identity string `json:"identity"`
		}
		if json.Unmarshal(e.Payload, &p) == nil {
			perID[p.Identity]++
		}
	}
	ids := make([]string, 0, len(perID))
	for id := range perID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	denied := 0
	for _, id := range ids {
		decision := "ALLOW"
		if perID[id] > pol.MaxIssuesPerIdentityPerWindow {
			decision = "DENY"
			denied++
		}
		fmt.Printf("%-24s %-5s (%d issues, limit %d)\n", id, decision, perID[id], pol.MaxIssuesPerIdentityPerWindow)
	}
	fmt.Printf("PDP: %d ALLOW, %d DENY, %d identities evaluated\n", len(ids)-denied, denied, len(ids))
	return nil
}

func load(eventsFile string) (*to.Timeline, error) {
	tl, err := to.LoadTimeline(eventsFile)
	if err != nil {
		return nil, err
	}
	if len(tl.Events()) == 0 {
		return nil, errors.New("no events in timeline")
	}
	return tl, nil
}
