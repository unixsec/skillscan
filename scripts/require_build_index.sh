#!/bin/sh
# INV-14 build-time egress gate. Refuses a build that has not said, explicitly,
# where its packages come from.
#
# WHY THIS EXISTS. Three build args point the three package managers at an
# internal mirror: PIP_INDEX_URL, NPM_CONFIG_REGISTRY, GOPROXY. Every one of
# them treats an EMPTY value as "not set" and silently falls back to its own
# PUBLIC default - measured on the dev VM 2026-07-30, not assumed:
#
#   UV_INDEX_URL=""          -> resolves all 74 locked packages from pypi.org
#   NPM_CONFIG_REGISTRY=""   -> `npm config get registry` = registry.npmjs.org
#   GOPROXY=""               -> `go env GOPROXY` = https://proxy.golang.org,direct
#
# So the whole system's zero-external-egress invariant had a hole in the one
# phase nobody watches, and the hole was INVISIBLE: an operator who set
# SKILLSCAN_PIP_INDEX_URL= in .env (which is what `cp .env.example .env`
# produces) got a build that looked configured and reached the public internet
# anyway. That is the same empty-string-vs-absent-key defect class as
# SESSION_INTROSPECTION's, in a place with security consequences.
#
# THE FIX IS NOT "HARD-FAIL ALWAYS". Requiring a mirror to build at all would
# break every developer laptop, this repo's own CI, and scripts/
# build_offline_bundle.sh (whose entire job is to run WHERE THERE IS INTERNET
# and carry the result inside). A gate people cannot satisfy gets deleted, or
# worse, worked around by editing the Dockerfile. So public is still reachable -
# it just has to be ASKED FOR, by name, in a way that shows up in the build
# command, the compose file and `docker history`. Unset and empty now behave
# identically, and neither of them means "public".
#
# Usage (from a Dockerfile RUN, after the matching ARGs are declared):
#   require_build_index.sh <ARG_NAME> "<ARG_VALUE>" "<ALLOW_PUBLIC_INDEXES>" <public-default>
set -eu

arg_name="${1:?usage: require_build_index.sh ARG_NAME ARG_VALUE ALLOW_PUBLIC public-default}"
arg_value="${2:-}"
allow_public="${3:-}"
public_default="${4:?missing public-default}"

# An explicitly configured index wins, always. This is the air-gapped path.
if [ -n "$arg_value" ]; then
    echo "build index: ${arg_name}=${arg_value}"
    exit 0
fi

# Public, but on the record.
if [ "$allow_public" = "true" ]; then
    echo "build index: ${arg_name} is not set and ALLOW_PUBLIC_INDEXES=true -" \
         "this build WILL reach ${public_default} (INV-14 waived deliberately)"
    exit 0
fi

echo "" >&2
echo "!!! INV-14: this build has no package index configured, and refusing is the" >&2
echo "!!! only honest answer - leaving ${arg_name} empty does NOT fail closed, it" >&2
echo "!!! silently uses ${public_default}." >&2
echo "!!!" >&2
echo "!!! Pick one, explicitly:" >&2
echo "!!!" >&2
echo "!!!   internal mirror (the air-gapped path):" >&2
echo "!!!     docker build --build-arg ${arg_name}=https://<your-mirror>/..." >&2
echo "!!!     docker compose: set SKILLSCAN_${arg_name} in .env" >&2
echo "!!!" >&2
echo "!!!   public internet, deliberately (dev laptop, CI, offline-bundle build):" >&2
echo "!!!     docker build --build-arg ALLOW_PUBLIC_INDEXES=true" >&2
echo "!!!     docker compose: set SKILLSCAN_ALLOW_PUBLIC_INDEXES=true in .env" >&2
echo "!!!" >&2
echo "!!! NOTE apt is deliberately NOT covered by this gate - see the APT section" >&2
echo "!!! of docs/DEPLOYMENT_GUIDE.md §0 for why, and for what an air-gapped build" >&2
echo "!!! has to do instead." >&2
echo "" >&2
exit 1
