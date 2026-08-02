# Trust Orchestrator — make targets (deployment guide §3, §7, §10).
# Requires: Go 1.22+, Java 21+ (model check only).

BIN      := bin
GO       := go

.PHONY: all build test benchmark kill-tests model-check model-check-mutations clean

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

clean:
	rm -rf $(BIN) reports bootstrap.key shard-*.json node.key node.cert.json
