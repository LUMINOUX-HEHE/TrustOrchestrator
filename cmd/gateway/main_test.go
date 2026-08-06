package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	to "trustorchestrator"
)

// The dashboard embed and the API must both answer under the same handler.
func TestDashboardAndAPI(t *testing.T) {
	gw, token, err := to.NewGateway(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(gw))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Trust Orchestrator") {
		t.Fatalf("dashboard: %d, %d bytes", resp.StatusCode, len(body))
	}
	if !strings.Contains(string(body), "id=\"token\"") {
		t.Fatal("dashboard missing token input")
	}

	// API still answers through the same mux
	req, _ := http.NewRequest("GET", srv.URL+"/v1/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("api under dashboard mux: %d", resp.StatusCode)
	}
}
