#!/bin/sh
# Print the release version `vendor/engines.lock.yaml` pins for ONE engine, so a
# Dockerfile can (a) feed that number into a build that needs it and (b) assert
# afterwards that the binary it actually produced reports the same number.
#
# WHY THIS EXISTS (INV-7): the ruleset digest feeds `toolchain_digest`, which
# feeds `cache_key`, and that whole chain assumes the digest identifies the
# toolchain that RAN. Until 2026-07-29 it did not: engines.lock.yaml recorded
# yara v4.5.7 while services/engine_runner/Dockerfile apt-installed Debian
# bookworm's yara 4.2.3, so every digest fingerprinted a toolchain that never
# executed. A comment cannot stop that from happening again; a build step that
# exits non-zero when the two disagree can. This script is the shared half of
# that guard - the comparison itself stays in each Dockerfile, right next to the
# binary it is checking.
#
# Usage (repo root as build context; both arguments are required):
#   scripts/vendor_pinned_version.sh <lock-file> <engine-key>
#   scripts/vendor_pinned_version.sh vendor/engines.lock.yaml yara   -> 4.5.7
#
# DELIBERATE `#!/bin/sh` + POSIX awk, against this project's usual
# `#!/bin/bash` + `set -euo pipefail` convention: this runs INSIDE the engine
# build images, not on a developer machine. `debian:bookworm-slim` and
# `python:3.12-slim-bookworm` both ship bash, but `deploy/engines/osv_scanner/
# Dockerfile`'s runtime stage is alpine, which does not - and a helper whose
# whole job is to stop the four engine Dockerfiles from drifting apart must not
# itself be unusable in one of them. `awk` IS present in all three bases
# (verified, 2026-07-29). It also deliberately does NOT use a YAML library:
# the yara builder stage is plain Debian with no Python at all.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <engines.lock.yaml> <engine-key>" >&2
    exit 2
fi

lock_file="$1"
engine_key="$2"

if [ ! -f "$lock_file" ]; then
    echo "!!! $0: no such lock file: $lock_file" >&2
    exit 1
fi

# Reads the `tag:` recorded at indent 4 under the `  <engine>:` key at indent 2,
# which is exactly engines.lock.yaml's shape. `inblk` is reset on EVERY indent-2
# key, so a `tag:` belonging to a different engine can never be returned for the
# one asked for - the failure this would otherwise produce (silently asserting
# bandit against osv-scanner's version) is precisely the class of mix-up this
# script is supposed to prevent. Trailing `# ...` comments and surrounding
# double quotes are stripped (`bandit` records its tag as `"1.9.4"`).
pinned="$(
    awk -v key="$engine_key" '
        /^  [A-Za-z_][A-Za-z0-9_]*:[ \t]*$/ {
            inblk = ($0 == "  " key ":") ? 1 : 0
            next
        }
        inblk && /^    tag:[ \t]/ {
            value = $0
            sub(/^[ \t]*tag:[ \t]*/, "", value)
            sub(/[ \t]*#.*$/, "", value)
            gsub(/"/, "", value)
            sub(/[ \t]+$/, "", value)
            print value
            exit
        }
    ' "$lock_file"
)"

if [ -z "$pinned" ]; then
    # Fails closed rather than printing an empty string: an empty expected
    # version would make every `[ "$built" = "$expected" ]` comparison
    # downstream fail confusingly, or - worse, if a caller ever compared
    # loosely - pass against anything. `skillspector` legitimately has no tag
    # (pinned to a bare commit, no upstream release), so this is also the
    # correct answer for "this engine has no assertable version".
    echo "!!! $0: $lock_file records no 'tag:' for engine '$engine_key'" >&2
    exit 1
fi

# Upstream tags are inconsistent about the `v` prefix (yara `v4.5.7`,
# osv-scanner `v2.4.0`, bandit `1.9.4`) but no engine's CLI prints it. Strip it
# here, once, so each Dockerfile can compare with plain string equality instead
# of re-inventing the normalization per engine.
printf '%s\n' "${pinned#v}"
