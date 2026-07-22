# Pin-digest build image for the `osv-scanner` OSS engine (coding spec §10A).
# Adapted from vendor/osv-scanner/Dockerfile (the engine's own upstream
# Dockerfile, which already digest-pins its base images - those real digests
# are reused below verbatim rather than re-guessed) - not written from
# scratch. Modified to build from the already-vendored source tree instead of
# `go mod download`ing against the public Go proxy.
#
# Build context MUST be the repo root:
#   docker build -f deploy/engines/osv_scanner/Dockerfile \
#     --build-arg GOPROXY=https://goproxy.internal.example \
#     -t skillscan-engine-osv-scanner:2.4.0 .
#
# SECURITY (INV-15/§10A/INV-14): no `git clone` here - `COPY` pulls the
# already-vendored, pinned source out of vendor/osv-scanner (see
# vendor/engines.lock.yaml's commit pin). `go mod download` still needs SOME
# module proxy (osv-scanner's own go.sum lists its dependency graph, but this
# repo does not vendor osv-scanner's OWN Go module dependencies, only
# osv-scanner's own source - see VENDOR.md); GOPROXY has NO default here on
# purpose, forcing an operator to point it at the enterprise's internal Go
# proxy mirror. An unset GOPROXY falls back to Go's built-in
# `https://proxy.golang.org,direct` default, which is NOT the fail-closed
# behavior this project wants - `GOFLAGS=-mod=mod GOPROXY=off` would fail
# instead, so this Dockerfile explicitly sets GOPROXY from the ARG with no
# fallback and relies on the operator supplying it (documented here rather
# than silently assumed solved - matches the M4 intel_sync.py/M5
# skillspector.py precedent for gaps this repo's own code can't close alone).
# --offline at RUN time (INV-14) is enforced by the adapter's argv
# (services/engine_runner/adapters/osv.py), not by this build stage.
#
# NOT VERIFIED: no Docker daemon is available in this development environment
# - this Dockerfile has not been built here (same posture as bandit's
# Dockerfile in this same directory tree).
FROM golang:1.26.4-alpine3.23@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder

ARG GOPROXY

WORKDIR /src
COPY vendor/osv-scanner/ ./

# SECURITY: GOPROXY has no default - an operator who forgets to pass
# --build-arg GOPROXY gets Go's own error for an unreachable/unset proxy
# rather than a silent public-internet fetch.
ENV GOPROXY=${GOPROXY}
RUN go mod download
RUN go build -o osv-scanner ./cmd/osv-scanner/

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

RUN apk --no-cache add ca-certificates

WORKDIR /scan
COPY --from=builder /src/osv-scanner /usr/local/bin/osv-scanner

ENTRYPOINT ["/usr/local/bin/osv-scanner"]
