# Trust Orchestrator container image (deployment guide §12 K8s).
# One image, all 9 binaries in /bin/ — each Deployment picks its own
# entrypoint. Scratch base: the CLIs are static (CGO_ENABLED=0) and use only
# the identity CA for mTLS, no OS cert bundle needed.
# Build: make docker-build

FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/to-tool ./cmd/to \
 && cp /out/to-tool /out/to-bench \
 && cp /out/to-tool /out/to-watchdog \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/to-orchestrator ./cmd/orchestrator \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/to-council ./cmd/council \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/to-auditor ./cmd/auditor \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/to-identity ./cmd/identity \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/to-pdp ./cmd/pdp \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/to-dnsprobe ./cmd/dnsprobe

FROM scratch
COPY --from=build /out/ /bin/
ENTRYPOINT ["/bin/to-tool"]
