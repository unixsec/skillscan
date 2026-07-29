# engine-runner build image (coding spec §10/§11.7, INV-10).
#
# SECURITY: this image ends up holding zero DB/Vault/IdP credentials at
# runtime (see deploy/helm/skillscan/templates/engine-runner-deployment.yaml's
# env list) - only SKILLSCAN_REDIS_URL and the two engine-specific endpoints
# (SKILLSCAN_VLLM_BASE_URL, SKILLSCAN_OSV_SOURCE). Mirrors
# apps/monolith/Dockerfile's build shape for consistency, not because this
# service needs anything the monolith needs beyond the shared uv/venv layout.
#
# ALL FIVE ENGINES ARE NOW BUILT FROM `vendor/` (2026-07-29). Until that date
# two of them were not: bandit came from PyPI (`uv pip install bandit==1.9.4`)
# and yara from the Debian archive. Both reasons had expired - the vendored
# trees stopped being git submodules that day and are ordinary committed
# source, hash-verified against their upstream pins by
# `scripts/vendor_engines.py verify-pins`.
#
# EVERY VERSION IN THIS IMAGE IS ASSERTED AGAINST engines.lock.yaml, in the
# build, by the final stage's verification step - not in a comment. INV-7
# chains ruleset digest -> `toolchain_digest` -> `cache_key`, and that chain is
# only meaningful if the digest names the toolchain that actually ran. The old
# apt-installed yara was 4.2.3 against a lock file recording v4.5.7, so every
# digest fingerprinted a toolchain that never executed. A drift like that is
# invisible to review and to every test that does not run the real binary, so
# the build itself now refuses to produce an image whose engines disagree with
# the pins.
#
# bandit: built from the real vendored source (vendor/bandit, pinned tag 1.9.4)
# via `uv pip install` of the local tree. NOTE, honestly: bandit's packaging is
# `pbr`-based (setup.py: `setup_requires=["pbr>=2.0.0"], pbr=True`) and pbr
# derives the version from GIT TAGS, which a vendored subtree cannot carry -
# an unassisted `pip install .` fails outright with "Versioning for this
# project requires either an sdist tarball, or access to an upstream git
# repository" (confirmed live on the dev VM, 2026-07-29). `PBR_VERSION` is
# therefore fed in FROM engines.lock.yaml. That makes bandit's version
# assertion partly circular - we supply the number we then check - and it is
# worth being precise about what it does and does not prove. It does NOT
# independently corroborate that this source is 1.9.4; the tree hash in
# engines.lock.yaml is what does that. It DOES prove the install succeeded,
# that the CLI runs, and that the version `bandit --version` reports at
# runtime - which is what a toolchain digest would fingerprint - is the pinned
# one rather than something a later layer replaced. yara has no such caveat:
# its version comes from its own `configure.ac` (`AC_INIT([yara], [4.5.7])`),
# so its assertion is a genuine, independent cross-check.
# osv-scanner: built from the real vendored source (vendor/osv-scanner, pinned
# v2.4.0 per engines.lock.yaml) via a Go builder stage, adapted from
# deploy/engines/osv_scanner/Dockerfile's already-authored recipe (same base
# image digest, same `go build` invocation) rather than a separate per-engine
# image, so it lands in this single combined engine-runner image. `--offline`
# mode additionally needs a local vulnerability database
# (OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, per vendor/osv-scanner/docs/
# offline-mode.md) - a separate, genuinely external data fetch (Google's own
# GCS bucket) this Dockerfile does NOT perform; without it the binary runs
# and fails closed with an honest "no local database" error rather than
# reaching api.osv.dev (INV-14 preserved either way) - provisioning that
# database is a distinct, flagged-separately decision.
#
# skillspector: built from the real vendored source (vendor/skillspector,
# pinned commit dde36f2 - no upstream release tag) via `uv pip install` of
# the local source tree, same "install in the final stage" fix as bandit
# above (avoids the cross-build-stage shebang bug). It is the ONE engine the
# version guard cannot cover: with no upstream release tag there is no version
# to assert against, and `scripts/vendor_pinned_version.sh` fails closed for
# it rather than inventing one.
#
# aig-mcp-scan: only `vendor/aig/mcp-scan/` is copied in (NOT the whole
# 650k-line vendor/aig tree - the other subsystems there have no static/
# offline adapter, see engines.lock.yaml's aig entry), into its OWN isolated
# venv (`/app/.venv-aig`), never `uv pip install`ed into the shared
# `/app/.venv` alongside skillscan's own code - confirmed real conflict, not
# a hypothetical one: mcp-scan/requirements.txt pins pydantic==2.12.4, this
# project's own pyproject.toml pins pydantic==2.10.*, and both bandit and
# skillspector land in that same shared venv already. Isolating avoids
# silently upgrading pydantic under every other adapter and the service's
# own code to satisfy one LLM-only, currently-ungated-by-default engine.
#
# NOT VERIFIED beyond real builds+runs on the dev VM (10.211.55.10,
# 2026-07-08/09) - no gVisor RuntimeClass available there, same posture as
# every other Dockerfile in this repo.
FROM golang:1.26.4-alpine3.23@sha256:18b460dd17542c2ba43299a633cf6ebfc1115101509531471d7cfce1019af083 AS osv-builder

ARG GOPROXY
ARG ALLOW_PUBLIC_INDEXES

# INV-14 build-time egress gate, before `go mod download`. An empty GOPROXY does
# not fail closed - `go env GOPROXY` resolves to https://proxy.golang.org,direct
# (measured). See scripts/require_build_index.sh.
COPY scripts/require_build_index.sh /usr/local/bin/require_build_index.sh
RUN require_build_index.sh GOPROXY "${GOPROXY}" "${ALLOW_PUBLIC_INDEXES}" proxy.golang.org

WORKDIR /src
COPY vendor/osv-scanner/ ./
ENV GOPROXY=${GOPROXY}
RUN go mod download
RUN go build -o osv-scanner ./cmd/osv-scanner/

# yara: compiled from the real vendored source (vendor/yara, pinned v4.5.7 per
# engines.lock.yaml), adapted from deploy/engines/yara/Dockerfile's already-
# authored autotools recipe - same base image, same package list, same
# `bootstrap && configure && make` - rather than a separate per-engine image,
# so it lands in this single combined engine-runner image (exactly the
# relationship the osv-builder stage above has to deploy/engines/osv_scanner/).
#
# BUILDER STAGE, deliberately: autoconf/automake/libtool/bison/flex/gcc and the
# three -dev packages are ~250MB of toolchain that the runtime has no use for.
# Only the finished, stripped CLI crosses into the final stage.
#
# `--disable-shared` states explicitly what the single-file `COPY` below
# depends on. MEASURED, not assumed: a default build here already links libyara
# statically into the CLI (`ldd` on the resulting binary lists libcrypto,
# libmagic, libjansson, libm and libc - no libyara.so), so this flag changes
# nothing today. It is passed anyway because the COPY silently relies on that
# property, and an upstream default flip would produce an image whose `yara`
# dies at exec on a missing shared object - a failure that reads like a broken
# image rather than a build mistake.
#
# `--enable-magic --enable-cuckoo` reproduce the module set Debian's own yara
# package was built with (measured on the outgoing 4.2.3 image: it linked
# libmagic.so.1 and libjansson.so.4), so this swap is a version upgrade and not
# a silent capability regression. None of this project's own rules
# (policies/yara/*.yar) `import` any module today, but an operator's added rule
# may, and losing a module here would surface as a rule that simply never
# matches. Crypto (openssl, for the `hash` module) is on by default when the
# headers are present, and libssl-dev below keeps it that way.
#
# `vendor/yara/m4/acx_pthread.m4` IS required by this build, not incidental
# vendoring: configure.ac:88 calls `ACX_PTHREAD(...)` and Makefile.am sets
# `ACLOCAL_AMFLAGS=-I m4`, so `./bootstrap.sh` (`autoreconf --force --install`)
# fails to expand that macro without it. Today's vendoring had to force this
# file past an ignore rule; if it is ever lost, this stage is where it breaks.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS yara-builder

# The package list is taken from the real upstream CI recipe
# (vendor/yara/.github/workflows/build.yml), per coding spec §10A.3's "读真实
# vendor 源码,不臆测接口" applied to the build system too - and then verified by
# actually running it: an earlier attempt omitting bison/flex failed with
# "flex: command not found" on libyara/lexer.c, because .l/.y sources are
# regenerated after `autoreconf --force`.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        autoconf \
        automake \
        libtool \
        pkg-config \
        bison \
        flex \
        make \
        gcc \
        libjansson-dev \
        libmagic-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/yara
COPY vendor/yara/ ./
RUN ./bootstrap.sh \
    && ./configure --disable-shared --enable-magic --enable-cuckoo \
    && make -j"$(nproc)" \
    && strip yara

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS builder

ARG PIP_INDEX_URL
ARG ALLOW_PUBLIC_INDEXES

# INV-14 build-time egress gate - see scripts/require_build_index.sh.
COPY scripts/require_build_index.sh /usr/local/bin/require_build_index.sh
RUN require_build_index.sh PIP_INDEX_URL "${PIP_INDEX_URL}" "${ALLOW_PUBLIC_INDEXES}" pypi.org

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5@sha256:7bff3c3776ec467fc1437960f2c469d8beb30f536a6465a3350c647ccd260ec2 /uv /uvx /usr/local/bin/

WORKDIR /build
COPY pyproject.toml uv.lock ./
COPY libs/ libs/
COPY apps/ apps/
COPY services/ services/
COPY policies/ policies/
RUN UV_INDEX_URL="${PIP_INDEX_URL}" uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ARG PIP_INDEX_URL

ARG ALLOW_PUBLIC_INDEXES

# INV-14 build-time egress gate. This stage matters as much as the builder: it
# runs THREE `uv pip install` steps of its own (bandit, skillspector and
# aig-mcp-scan's requirements.txt), so an unconfigured index here reaches
# pypi.org just as silently. Removed again at the bottom of this stage, next to
# the version guard's own cleanup - a build-time helper has no business in the
# runtime image.
COPY scripts/require_build_index.sh /usr/local/bin/require_build_index.sh
RUN require_build_index.sh PIP_INDEX_URL "${PIP_INDEX_URL}" "${ALLOW_PUBLIC_INDEXES}" pypi.org

# `yara` itself is NOT installed here any more - it is compiled from
# vendor/yara in the yara-builder stage above and copied in below. What apt
# still provides is the two shared libraries that binary links against and
# `python:3.12-slim-bookworm` does not already carry (measured: the base image
# has libcrypto.so.3, but neither libmagic.so.1 nor libjansson.so.4). Dropping
# the `yara` package also drops `libyara9`, which nothing links against once
# libyara is statically inside the CLI.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        libjansson4 \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10002 engine-runner

COPY --from=ghcr.io/astral-sh/uv:0.5@sha256:7bff3c3776ec467fc1437960f2c469d8beb30f536a6465a3350c647ccd260ec2 /uv /uvx /usr/local/bin/
COPY --from=builder /build/.venv /app/.venv
COPY --from=osv-builder /src/osv-scanner /usr/local/bin/osv-scanner
COPY --from=yara-builder /build/yara/yara /usr/local/bin/yara
COPY policies/yara/ /app/policies/yara/
COPY vendor/skillspector/ /tmp/skillspector-src/
COPY vendor/bandit/ /tmp/bandit-src/
# The pin manifest and its reader travel INTO the image so the verification
# step at the bottom of this stage reads the same file the rest of the repo
# treats as authoritative, instead of a version transcribed into this
# Dockerfile - a transcription is exactly what drifted for yara.
COPY vendor/engines.lock.yaml /tmp/engines.lock.yaml
COPY scripts/vendor_pinned_version.sh /usr/local/bin/vendor_pinned_version.sh
ENV PATH="/app/.venv/bin:$PATH"
# SECURITY/CORRECTNESS: installed HERE, in the final stage, not the builder -
# `uv pip install`'s generated console-script shebangs bake in an ABSOLUTE
# interpreter path at install time (confirmed live: installing in the
# builder stage produced `#!/build/.venv/bin/python`, which silently doesn't
# exist once `.venv` is copied to `/app/.venv` in the final stage - every
# invocation failed with a misleading "No such file or directory: 'bandit'",
# indistinguishable from a missing binary, even though the file itself was
# present and executable). Installing after the venv is already at its real
# runtime path avoids the mismatch entirely, at the cost of a few more MB
# for `uv`/`uvx` themselves in the final image (acceptable for this dev
# build; a leaner build could `rm` them after this step).
#
# NETWORK, stated plainly: installing bandit from the local tree removes the
# dependency on PyPI serving *bandit's own source*, but NOT on an index. pbr
# (build backend), PyYAML, stevedore and rich are still resolved from
# PIP_INDEX_URL at build time - vendoring bandit's source does not vendor
# bandit's dependency graph, exactly as vendoring osv-scanner's source did not
# vendor its Go modules. docs/DEPLOYMENT_GUIDE.md §0.4 carries the full table.
RUN BANDIT_PIN="$(vendor_pinned_version.sh /tmp/engines.lock.yaml bandit)" \
    && PBR_VERSION="${BANDIT_PIN}" UV_INDEX_URL="${PIP_INDEX_URL}" \
        uv pip install --python /app/.venv/bin/python /tmp/bandit-src \
    && rm -rf /tmp/bandit-src
RUN UV_INDEX_URL="${PIP_INDEX_URL}" uv pip install --python /app/.venv/bin/python /tmp/skillspector-src \
    && rm -rf /tmp/skillspector-src

# aig-mcp-scan: isolated venv, see the header comment above for why this
# can't share /app/.venv. Only mcp-scan/ is copied - not the rest of
# vendor/aig, which has no static adapter (engines.lock.yaml's aig entry).
COPY vendor/aig/mcp-scan/ /app/vendor-aig-mcp-scan/
RUN uv venv /app/.venv-aig --python python3.12 \
    && UV_INDEX_URL="${PIP_INDEX_URL}" uv pip install --python /app/.venv-aig/bin/python \
        -r /app/vendor-aig-mcp-scan/requirements.txt

# ---------------------------------------------------------------------------
# VERSION GUARD (INV-7). Runs every engine binary this image actually ships and
# refuses to produce the image if any of them reports a version other than the
# one vendor/engines.lock.yaml pins.
#
# This is the acceptance criterion for building from vendor/, expressed as a
# build step rather than a comment, because a comment is precisely what failed:
# the outgoing image documented its own yara version gap accurately and shipped
# 4.2.3 against a lock recording v4.5.7 for months. `toolchain_digest` (and the
# `cache_key` derived from it) is computed from the lock file's contents, so a
# disagreement here means every digest names a toolchain that never ran, every
# cache hit is against results a different binary produced, and nothing
# downstream can detect it - the numbers all stay internally consistent.
#
# Deliberately the LAST step of the stage: it checks the binaries as they will
# be shipped, after every install has run, so a later layer that replaced one
# of them cannot slip past. skillspector is absent on purpose - it is pinned to
# a bare upstream commit with no release tag, so it has no version to assert
# (see the header). The pin manifest and its reader are removed afterwards: a
# copy of engines.lock.yaml sitting unread inside the runtime image is another
# second copy waiting to go stale, and this stage is the only thing that needed
# it.
RUN set -eu; \
    yara_pin="$(vendor_pinned_version.sh /tmp/engines.lock.yaml yara)"; \
    bandit_pin="$(vendor_pinned_version.sh /tmp/engines.lock.yaml bandit)"; \
    osv_pin="$(vendor_pinned_version.sh /tmp/engines.lock.yaml osv_scanner)"; \
    yara_built="$(yara --version)"; \
    bandit_built="$(bandit --version 2>&1 | head -1 | awk '{print $2}')"; \
    osv_built="$(osv-scanner --version 2>&1 | head -1 | awk '{print $3}')"; \
    echo "yara         built=${yara_built}   pinned=${yara_pin}"; \
    echo "bandit       built=${bandit_built}   pinned=${bandit_pin}"; \
    echo "osv-scanner  built=${osv_built}   pinned=${osv_pin}"; \
    rc=0; \
    [ "$yara_built" = "$yara_pin" ] || { echo "!!! yara ${yara_built} != pinned ${yara_pin}" >&2; rc=1; }; \
    [ "$bandit_built" = "$bandit_pin" ] || { echo "!!! bandit ${bandit_built} != pinned ${bandit_pin}" >&2; rc=1; }; \
    [ "$osv_built" = "$osv_pin" ] || { echo "!!! osv-scanner ${osv_built} != pinned ${osv_pin}" >&2; rc=1; }; \
    if [ "$rc" -ne 0 ]; then \
        echo "!!! a shipped engine disagrees with vendor/engines.lock.yaml." >&2; \
        echo "!!! toolchain_digest is computed from that lock file (INV-7), so this" >&2; \
        echo "!!! image would fingerprint a toolchain it does not contain. Refusing." >&2; \
        exit 1; \
    fi; \
    rm -f /tmp/engines.lock.yaml /usr/local/bin/vendor_pinned_version.sh \
          /usr/local/bin/require_build_index.sh

USER engine-runner
WORKDIR /app
ENTRYPOINT ["python", "-m", "engine_runner.main"]
