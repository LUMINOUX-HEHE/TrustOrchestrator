// to-gateway: the management plane — REST API, RBAC, multi-tenancy, webhooks,
// backup/restore over the trust engine, plus the web dashboard at /.
// State lives under -data.
//
//	to-gateway -addr :8080 -data ./data
//
// First boot prints the admin token (or -token/TO_ADMIN_TOKEN seeds it).
package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	to "trustorchestrator"
)

//go:embed dashboard.html
var dashboardFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	data := flag.String("data", "./data", "state directory")
	token := flag.String("token", os.Getenv("TO_ADMIN_TOKEN"), "admin bootstrap token (first boot only)")
	flag.Parse()

	gw, raw, err := to.NewGateway(*data, *token)
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	if raw != "" {
		fmt.Printf("admin token (shown once): %s\n", raw)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newHandler(gw),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("trust orchestrator gateway on %s (data: %s)", *addr, *data)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// newHandler mounts the dashboard at / and the REST API everywhere else.
func newHandler(gw *to.Store) http.Handler {
	dash, _ := dashboardFS.ReadFile("dashboard.html")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dash)
	})
	mux.Handle("/", gw.Handler())
	return mux
}
