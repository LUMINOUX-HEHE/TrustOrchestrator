# Trust Orchestrator — make targets (deployment guide §3, §7, §10, §12).
# Requires: Go 1.24+, Java 21+ (model check only).

BIN      := bin
GO       := go
DOCKER   := docker
GOOS_    := linux
GOARCH_  := amd64

.PHONY: all build build-linux test benchmark kill-tests model-check model-check-gateway model-check-pq model-check-extra model-check-mutations model-check-mutations-extra fleet-smoke docker-build helm-lint terraform-validate sbom clean

all: build

build:
	$(GO) build -o $(BIN)/to-tool ./cmd/to
	$(GO) build -o $(BIN)/to-bench ./cmd/to       # guide §10 binary name; same CLI
	$(GO) build -o $(BIN)/to-watchdog ./cmd/to     # guide §5 binary name; same CLI (enroll/run)
	$(GO) build -o $(BIN)/to-orchestrator ./cmd/orchestrator
	$(GO) build -o $(BIN)/to-council ./cmd/council
	$(GO) build -o $(BIN)/to-auditor ./cmd/auditor
	$(GO) build -o $(BIN)/to-identity ./cmd/identity
	$(GO) build -o $(BIN)/to-pdp ./cmd/pdp
	$(GO) build -o $(BIN)/to-dnsprobe ./cmd/dnsprobe
	$(GO) build -o $(BIN)/to-gateway ./cmd/gateway    # REST API + dashboard (phase 2)

# build-linux: cross-compile the same 10 binaries for linux/amd64 from any
# host. No cgo, stdlib-only crypto (Ed25519/TLS) — this target is the port
# check: it must produce runnable linux ELFs without touching Linux. The
# systemd units in deploy/ run exactly these binaries.
build-linux:
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-tool ./cmd/to
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-bench ./cmd/to
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-watchdog ./cmd/to
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-orchestrator ./cmd/orchestrator
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-council ./cmd/council
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-auditor ./cmd/auditor
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-identity ./cmd/identity
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-pdp ./cmd/pdp
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-dnsprobe ./cmd/dnsprobe
	GOOS=$(GOOS_) GOARCH=$(GOARCH_) $(GO) build -o $(BIN)/linux/to-gateway ./cmd/gateway

# fleet-smoke: live-fleet proof — 4 real processes over mTLS on one host
# (deploy/fleet-smoke.sh, deployment guide §5).
fleet-smoke:
	bash deploy/fleet-smoke.sh

# docker-build: the container image (guide §12 K8s). Static, stdlib-only —
# scratch base, no OS cert bundle. Requires docker; the same binaries are
# verified as linux ELFs by build-linux and CI.
docker-build:
	$(DOCKER) build -t trust-orchestrator:latest .

# helm-lint: validate the chart (requires helm).
helm-lint:
	helm lint helm/trust-orchestrator

# terraform-validate: check all three cloud modules (requires terraform).
terraform-validate:
	cd terraform/aws && terraform fmt -check -recursive && terraform validate
	cd terraform/azure && terraform fmt -check -recursive && terraform validate
	cd terraform/gcp && terraform fmt -check -recursive && terraform validate

# sbom: per-binary software bill of materials via `go version -m` (module,
# toolchain, VCS provenance) into reports/sbom.txt. No third-party tooling:
# the module is stdlib-only, so there is no dependency tree to emit.
sbom: build
	for f in $(wildcard $(BIN)/to-*); do echo "== $$f"; $(GO) version -m "$$f"; done | tee reports/sbom.txt

test:
	$(GO) test ./...

benchmark:
	$(GO) run ./cmd/to bench run --scenario all --out reports --log reports/action-log.txt

kill-tests:          # test-plan §7, deliverables: kill-test logs
	$(GO) test -run '^TestK' -v ./... | tee reports/kill-tests.log

model-check:         # P1-P4/P6 on the base spec; writes reports/tlc.log (guide §3)
	cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
		-config TrustOrchestrator.cfg TrustOrchestrator.tla 2>&1 | tee ../reports/tlc.log

model-check-mutations:   # P2/P6 mutation tests (test plan §3): TLC must report a violation
	cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
		-config TrustOrchestratorP2Mutant.cfg TrustOrchestratorP2Mutant.tla 2>&1 | tee ../reports/mutation-p2.log | grep -q "Invariant Safety is violated"
	cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
		-config TrustOrchestratorP6Mutant.cfg TrustOrchestratorP6Mutant.tla 2>&1 | tee ../reports/mutation-p6.log | grep -q "Invariant Safety is violated"

# model-check-gateway / model-check-pq: the P7 (gateway fork adoption) and
# P8 (hybrid PQ handshake) invariants — the API layer beyond the core
# engine. model-check-extra runs both.
model-check-gateway:     # P7: adoption gate — quorum, prefix descent, epoch monotonic
	cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
		-config Gateway.cfg Gateway.tla 2>&1 | tee ../reports/tlc-gateway.log | grep -q "No error has been found"

model-check-pq:          # P8: established session requires both hybrid halves untampered
	cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
		-config PQHandshake.cfg PQHandshake.tla 2>&1 | tee ../reports/tlc-pq.log | grep -q "No error has been found"

model-check-extra: model-check-gateway model-check-pq

model-check-mutations-extra:   # P7/P8 mutation tests: TLC must report a violation
	cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
		-config GatewayP7Mutant.cfg GatewayP7Mutant.tla 2>&1 | tee ../reports/mutation-p7.log | grep -q "Invariant Safety is violated"
	cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
		-config PQHandshakeMutant.cfg PQHandshakeMutant.tla 2>&1 | tee ../reports/mutation-pq.log | grep -q "Invariant Safety is violated"

clean:
	rm -rf $(BIN) reports bootstrap.key shard-*.json node.key node.cert.json
