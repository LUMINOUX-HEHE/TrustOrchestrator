// to-gateway: the management plane — REST API, RBAC, multi-tenancy, webhooks,
// backup/restore over the trust engine, plus the web dashboard at /.
// State lives under -data.
//
//	to-gateway -addr :8080 -data ./data
//	to-gateway -addr :8443 -tls-cert cert.pem -tls-key key.pem   # TLS
//	to-gateway -council-pub <hex>                                # recovery anchor
//
// First boot prints the admin token (or -token/TO_ADMIN_TOKEN seeds it).
package main

import (
	"crypto/ed25519"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	to "trustorchestrator"
)

//go:embed dashboard.html
var dashboardFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	data := flag.String("data", "./data", "state directory")
	token := flag.String("token", os.Getenv("TO_ADMIN_TOKEN"), "admin bootstrap token (first boot only)")
	tlsCert := flag.String("tls-cert", "", "server certificate (enables TLS; needs tls-key)")
	tlsKey := flag.String("tls-key", "", "server private key")
	council := flag.String("council-pub", os.Getenv("TO_COUNCIL_PUB"), "hex council FROST group key — recovery trust anchor")
	lock := flag.String("leader-lock", "", "peer file: HA single-writer lease (second gateway exits)")
	kekShares := flag.String("kek-shares", "", "council KEK share files, comma-separated — 3-of-5 threshold unwrap for gateway.keys (envelope encryption, vault.go)")
	flag.Parse()

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("gateway: tls-cert and tls-key must be set together")
	}
	if *lock != "" {
		acquireLeaderLock(*lock)
		defer os.Remove(*lock)
	}

	gw, raw, err := to.NewGateway(*data, *token)
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	if *kekShares != "" {
		shares, err := loadShares(*kekShares)
		if err != nil {
			log.Fatalf("gateway: kek-shares: %v", err)
		}
		if err := gw.UnlockVault(shares); err != nil {
			log.Fatalf("gateway: vault unwrap: %v", err)
		}
		log.Printf("vault: envelope encryption active (council KEK, unwrapped by %d share files)", len(shares))
	}
	if *council != "" {
		pub, err := hex2key(*council)
		if err != nil {
			log.Fatalf("gateway: council-pub: %v", err)
		}
		if err := gw.SetCouncilPub(pub); err != nil {
			log.Fatalf("gateway: set council anchor: %v", err)
		}
	}
	gw.StartWebhookOutbox() // durable delivery on top of the gateway store
	if raw != "" {
		fmt.Printf("admin token (shown once): %s\n", raw)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newHandler(gw),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if *tlsCert != "" {
		log.Printf("trust orchestrator gateway on https://%s (data: %s, council: %t)", *addr, *data, *council != "")
		if err := srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
			log.Fatal(err)
		}
		return
	}
	log.Printf("trust orchestrator gateway on http://%s (data: %s, council: %t)", *addr, *data, *council != "")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// hex2key decodes a hex-encoded council FROST group key (32-byte Ed25519).
func hex2key(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// loadShares reads the council KEK share files (Shard JSON, one per member).
func loadShares(list string) ([]*to.Shard, error) {
	var shares []*to.Shard
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var sh to.Shard
		if err := json.Unmarshal(b, &sh); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		shares = append(shares, &sh)
	}
	if len(shares) == 0 {
		return nil, fmt.Errorf("no share files given")
	}
	return shares, nil
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

// acquireLeaderLock makes one gateway the single writer over a data dir:
// the lock file is created exclusively; a second process exits. HA = one
// active replica + the outbox survives restarts (ponytail: manual failover
// — the new replica takes over when the file is removed).
func acquireLeaderLock(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatalf("gateway: leader lock %s held by another instance (HA single-writer)", path)
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()
}
