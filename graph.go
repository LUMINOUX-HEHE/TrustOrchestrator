package trustorchestrator

import "encoding/json"

// SecurityGraph tracks trust edges over identities and certs (FR7.1).
// Nodes are prefixed: "id:<identity>" and "cert:<cert_id>". Edges carry the
// creating event. Derived from ISSUE events; always rebuildable (FR7.2).
type SecurityGraph struct {
	edges map[string]map[string]string
}

func NewSecurityGraph() *SecurityGraph {
	return &SecurityGraph{edges: map[string]map[string]string{}}
}

func (g *SecurityGraph) AddEdge(src, dst, via string) {
	if g.edges[src] == nil {
		g.edges[src] = map[string]string{}
	}
	g.edges[src][dst] = via
}

// Reachable returns all nodes reachable from from (BFS), including from
// itself. This is the scoped-recovery invalidation core (FR7.2, P5).
func (g *SecurityGraph) Reachable(from string) []string {
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for dst := range g.edges[cur] {
			if !seen[dst] {
				seen[dst] = true
				queue = append(queue, dst)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// BuildGraph derives the security graph from the timeline (FR7.1).
func BuildGraph(tl *Timeline) *SecurityGraph {
	g := NewSecurityGraph()
	for _, e := range tl.events {
		if e.Type != EvIssue {
			continue
		}
		var p issuePayload
		if json.Unmarshal(e.Payload, &p) != nil {
			continue
		}
		g.AddEdge("id:"+p.Identity, "cert:"+p.CertID, "issue:"+p.CertID)
		if p.Via != "" {
			g.AddEdge("cert:"+p.Via, "cert:"+p.CertID, "issue:"+p.CertID)
		}
	}
	return g
}
