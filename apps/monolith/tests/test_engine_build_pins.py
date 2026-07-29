"""Tests for the build-time engine version guard (INV-7).

WHAT THIS PROTECTS. `toolchain_digest` - and the `cache_key` derived from it -
is computed from `vendor/engines.lock.yaml`. That construction is only
meaningful if the lock file names the toolchain that actually RAN. Until
2026-07-29 it did not: the lock recorded yara `v4.5.7` while
`services/engine_runner/Dockerfile` apt-installed Debian bookworm's yara
`4.2.3`, so every digest fingerprinted a toolchain that never executed, and
every cache hit was against results a different binary had produced. Nothing
downstream could notice - the numbers all stayed internally consistent.

The fix is a build step that exits non-zero when a built engine disagrees with
its pin. These tests exist because that guard is only worth anything if it is
actually PRESENT in every Dockerfile that produces an engine binary, and this
repo has been bitten five separate times by "new thing added, the separate
registry that also had to know about it was not updated" - a defect class no
diff review catches. So the Dockerfile tests below DISCOVER the files they
check (glob `deploy/engines/*/Dockerfile`) rather than listing them: a sixth
engine directory added tomorrow is covered the day it lands, without anyone
remembering this file exists.

Exercised against the REAL lock file, the REAL helper script and the REAL
Dockerfiles - no fixtures. A fixture would prove nothing here, since the whole
point is to catch drift in actual repository state.

These tests need no MySQL/Redis/Docker: they read repository files and run a
POSIX shell script. They do NOT build images - the real build verification is a
VM step, recorded in
`.superpowers/sdd/2026-07-29-engine-management/vm-verification-checklist.md`.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LOCK_FILE = _REPO_ROOT / "vendor" / "engines.lock.yaml"
_HELPER = _REPO_ROOT / "scripts" / "vendor_pinned_version.sh"
_ENGINE_RUNNER_DOCKERFILE = _REPO_ROOT / "services" / "engine_runner" / "Dockerfile"
_PER_ENGINE_DIR = _REPO_ROOT / "deploy" / "engines"


def _run_helper(*args: str) -> subprocess.CompletedProcess[str]:
    # Invoked by path, not via `sh <path>`, on purpose: the Dockerfiles `COPY`
    # this script onto PATH and call it by bare name, so a lost executable bit
    # would break every one of those builds. Running it the same way the images
    # do makes that a test failure here instead of a build failure there.
    return subprocess.run(
        [str(_HELPER), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _lock_engines() -> dict[str, dict[str, object]]:
    payload = yaml.safe_load(_LOCK_FILE.read_text())
    engines = payload["engines"]
    assert isinstance(engines, dict)
    return engines


def _tagged_engines() -> list[str]:
    """Engine keys whose pin is a release tag, i.e. the ones with a version."""
    return sorted(key for key, spec in _lock_engines().items() if spec.get("tag"))


def _instructions(dockerfile: str) -> str:
    """The Dockerfile with comment lines removed.

    Assertions about what a build DOES must read the instructions, not the
    prose. These files carry long historical comments - including, deliberately,
    the exact `uv pip install bandit==1.9.4` line this change removed - and a
    naive substring search over the whole file reports the explanation of a
    fixed defect as the defect itself.
    """
    return "\n".join(line for line in dockerfile.splitlines() if not line.strip().startswith("#"))


def _apt_packages(dockerfile: str) -> set[str]:
    """Every package name any `apt-get install` in this Dockerfile asks for.

    Deliberately narrow. The question "is this engine installed from the distro
    archive instead of built from vendor/?" is only answerable by looking at
    apt's argument list - the engine's name legitimately appears elsewhere in
    these files (paths, stage names, shell variables in the version guard), and
    a looser match reports those as violations.

    Handles both layouts these Dockerfiles use: packages on the same line as
    `apt-get install`, and packages continued onto their own `\\`-terminated
    lines.
    """
    packages: set[str] = set()
    in_install = False
    for raw in dockerfile.splitlines():
        line = raw.strip()
        # Comments are not package lists. This matters specifically for
        # deploy/engines/yara/Dockerfile, whose prose explains at length why
        # yara is NOT apt-installed - swallowing those words would report the
        # very file that gets it right as a violation.
        if line.startswith("#"):
            continue
        continues = line.endswith("\\")
        line = line.removesuffix("\\").strip()
        if "apt-get install" in line:
            in_install = True
            line = line.split("apt-get install", 1)[1]
        elif not in_install:
            continue
        for token in line.split():
            # Skip flags, their values, and shell operators - what remains is a
            # package name.
            if token.startswith("-") or token in {"&&", "||", ";", "y", "true"}:
                continue
            if token.startswith(("$", "/", "rm", "apt-get")):
                continue
            packages.add(token)
        if not continues:
            in_install = False
    return packages


class TestVendorPinnedVersionHelper:
    def test_helper_is_executable(self) -> None:
        assert os.access(_HELPER, os.X_OK), (
            f"{_HELPER} must keep its executable bit - the engine Dockerfiles "
            "COPY it onto PATH and invoke it by bare name."
        )

    @pytest.mark.parametrize("engine", _tagged_engines())
    def test_reports_the_version_the_lock_file_pins(self, engine: str) -> None:
        # The helper's contract is "the pinned version, normalized", so it is
        # checked against the lock file parsed by a real YAML library - not
        # against a transcribed constant, which would just be a second place to
        # drift.
        expected = str(_lock_engines()[engine]["tag"]).lstrip("v")
        result = _run_helper(str(_LOCK_FILE), engine)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == expected

    def test_strips_the_v_prefix_upstream_tags_disagree_about(self) -> None:
        # yara tags `v4.5.7`, bandit tags `1.9.4`, and neither CLI prints a `v`.
        # Normalizing once, here, is what lets each Dockerfile compare with
        # plain string equality instead of re-inventing this per engine.
        assert _run_helper(str(_LOCK_FILE), "yara").stdout.strip() == "4.5.7"
        assert _run_helper(str(_LOCK_FILE), "bandit").stdout.strip() == "1.9.4"

    def test_fails_closed_for_an_engine_pinned_to_a_bare_commit(self) -> None:
        # skillspector has no upstream release tag. The helper must refuse
        # rather than print an empty string: an empty expected version makes
        # every downstream `[ "$built" = "$expected" ]` fail confusingly, and
        # under a looser comparison it would pass against anything.
        result = _run_helper(str(_LOCK_FILE), "skillspector")
        assert result.returncode != 0
        assert "no 'tag:'" in result.stderr
        assert result.stdout.strip() == ""

    def test_fails_closed_for_an_unknown_engine(self) -> None:
        result = _run_helper(str(_LOCK_FILE), "not_an_engine")
        assert result.returncode != 0
        assert result.stdout.strip() == ""

    def test_fails_closed_for_a_missing_lock_file(self) -> None:
        result = _run_helper("/nonexistent/engines.lock.yaml", "yara")
        assert result.returncode != 0
        assert result.stdout.strip() == ""

    def test_never_returns_a_different_engines_tag(self) -> None:
        # The specific mix-up this must never make: the helper walks a flat YAML
        # block, so a parser that failed to reset at each engine key would
        # happily return the previous engine's tag and every assertion built on
        # it would pass while checking the wrong thing.
        seen = {
            engine: _run_helper(str(_LOCK_FILE), engine).stdout.strip()
            for engine in _tagged_engines()
        }
        for engine, version in seen.items():
            assert version == str(_lock_engines()[engine]["tag"]).lstrip("v"), (
                f"{engine} resolved to {version}, which belongs to another engine"
            )


class TestEngineRunnerImageBuildsEveryEngineFromVendor:
    """The combined image skillscan actually deploys."""

    @pytest.fixture(scope="class")
    def dockerfile(self) -> str:
        return _ENGINE_RUNNER_DOCKERFILE.read_text()

    def test_bandit_comes_from_the_vendored_tree_not_an_index(self, dockerfile: str) -> None:
        # The exact regression: `uv pip install bandit==1.9.4` shipped whatever
        # the index served for that version string, not the tree this repo
        # vendored and whose hash `verify-pins` checks.
        assert "bandit==" not in _instructions(dockerfile), (
            "bandit must be installed from vendor/bandit, not pinned off an index"
        )
        assert "COPY vendor/bandit/" in dockerfile

    def test_yara_is_compiled_from_the_vendored_tree_not_the_debian_archive(
        self, dockerfile: str
    ) -> None:
        # The apt package is 4.2.3-4 on bookworm against a v4.5.7 pin - the
        # original digest lie. This has to look at the apt-get install package
        # lists SPECIFICALLY, not just anywhere `yara` appears: `libmagic1`/
        # `libjansson4` legitimately still come from apt, `WORKDIR /build/yara`
        # is fine, and the guard's own `yara_pin=`/`yara_built=` shell lines
        # begin with the four letters "yara" too. A naive substring or
        # startswith check matches those and fails for the wrong reason
        # (confirmed against the real file before this test was written).
        assert _apt_packages(dockerfile).isdisjoint({"yara", "yara-python"}), (
            "yara must be compiled from vendor/yara, not apt-installed"
        )
        assert "COPY vendor/yara/" in dockerfile
        assert "./bootstrap.sh" in dockerfile

    def test_the_yara_build_toolchain_stays_out_of_the_runtime_stage(self, dockerfile: str) -> None:
        # Multi-stage is the only reason compiling yara from source does not
        # add ~250MB of autotools/gcc to a runtime image. Measured on the dev
        # VM 2026-07-29: the whole switch cost +2.39MB.
        stages = dockerfile.split("\nFROM ")
        runtime_stage = stages[-1]
        for build_only in ("autoconf", "automake", "libtool", "bison", "flex", "gcc"):
            assert build_only not in runtime_stage, (
                f"{build_only} leaked into the runtime stage - it belongs in yara-builder"
            )

    def test_the_yara_builder_keeps_the_m4_macro_the_bootstrap_needs(self) -> None:
        # vendor/yara/m4/acx_pthread.m4 had to be forced past an ignore rule
        # during vendoring. configure.ac calls ACX_PTHREAD and Makefile.am sets
        # ACLOCAL_AMFLAGS=-I m4, so `autoreconf --force --install` cannot expand
        # that macro without it and the build fails in a way that looks like a
        # broken autotools install rather than a missing vendored file.
        macro = _REPO_ROOT / "vendor" / "yara" / "m4" / "acx_pthread.m4"
        configure_ac = (_REPO_ROOT / "vendor" / "yara" / "configure.ac").read_text()
        assert "ACX_PTHREAD" in configure_ac
        assert macro.is_file(), f"{macro} is required by vendor/yara/configure.ac's ACX_PTHREAD"

    @pytest.mark.parametrize("engine", ["yara", "bandit", "osv_scanner"])
    def test_asserts_every_version_the_lock_file_pins(self, dockerfile: str, engine: str) -> None:
        # Field-discovering in spirit: every engine that HAS a pinned version
        # must appear in the guard. skillspector is excluded by construction
        # (bare commit, no tag) rather than by being forgotten.
        assert f"vendor_pinned_version.sh /tmp/engines.lock.yaml {engine}" in dockerfile, (
            f"the version guard does not check {engine} against engines.lock.yaml"
        )

    def test_the_guard_reads_the_real_lock_file_rather_than_a_transcribed_version(
        self, dockerfile: str
    ) -> None:
        assert "COPY vendor/engines.lock.yaml" in dockerfile
        assert "COPY scripts/vendor_pinned_version.sh" in dockerfile

    def test_the_guard_can_actually_fail_the_build(self, dockerfile: str) -> None:
        # A guard that computes a comparison and then does not act on it is the
        # never-asserted-return-value defect this project has hit before. The
        # negative case was also verified for real on the dev VM (2026-07-29):
        # a deliberately tampered pin failed the build with exit code 1 and
        # produced no image.
        assert "exit 1" in dockerfile, "the version guard must fail the build, not just print"


class TestPerEngineDockerfilesAgreeWithTheCombinedImage:
    """`deploy/engines/` is a SECOND copy of the same recipe.

    It is driven by `.ci/pipeline.yml`'s image-sign job, and it drifted: its
    bandit Dockerfile could never build at all (pbr reads the version from git
    tags a vendored subtree does not carry), which went unnoticed because the
    directory's README declared that none of these had ever been built.
    """

    @pytest.mark.parametrize(
        "dockerfile",
        sorted(_PER_ENGINE_DIR.glob("*/Dockerfile")),
        ids=lambda p: p.parent.name,
    )
    def test_every_per_engine_dockerfile_builds_from_vendor(self, dockerfile: Path) -> None:
        engine_dir = dockerfile.parent.name
        text = dockerfile.read_text()
        assert "COPY vendor/" in text, (
            f"deploy/engines/{engine_dir}/Dockerfile must build from vendor/, "
            "never a git clone or a public package install"
        )

    @pytest.mark.parametrize(
        "dockerfile",
        sorted(_PER_ENGINE_DIR.glob("*/Dockerfile")),
        ids=lambda p: p.parent.name,
    )
    def test_every_per_engine_dockerfile_with_a_pinned_version_asserts_it(
        self, dockerfile: Path
    ) -> None:
        # DISCOVERY, not a hardcoded list: the engine key is taken from the
        # directory name and checked against the lock file, so adding
        # deploy/engines/<new>/Dockerfile for a tagged engine fails here until
        # it carries the guard too. That is the whole point - the five prior
        # "separate registry not updated" defects in this repo were all
        # invisible to diff review.
        engine_key = dockerfile.parent.name
        if engine_key not in _tagged_engines():
            pytest.skip(f"{engine_key} has no release tag pinned - no version to assert")
        text = dockerfile.read_text()
        assert "vendor_pinned_version.sh" in text, (
            f"deploy/engines/{engine_key}/Dockerfile builds a versioned engine but "
            "does not assert that version against vendor/engines.lock.yaml"
        )
        assert "exit 1" in text, (
            f"deploy/engines/{engine_key}/Dockerfile's version guard must fail the build"
        )

    def test_bandit_supplies_the_pbr_version_its_packaging_cannot_derive(self) -> None:
        # The concrete breakage: `pip install .` on a vendored bandit tree dies
        # with "Versioning for this project requires either an sdist tarball, or
        # access to an upstream git repository". Reproduced on the dev VM
        # 2026-07-29 before the fix, and again green after it.
        text = (_PER_ENGINE_DIR / "bandit" / "Dockerfile").read_text()
        assert "PBR_VERSION" in text, (
            "bandit's pbr packaging reads its version from git tags, which a "
            "vendored subtree does not carry - PBR_VERSION must be supplied"
        )

    def test_the_combined_image_supplies_it_too(self) -> None:
        assert "PBR_VERSION" in _ENGINE_RUNNER_DOCKERFILE.read_text()

    def test_yara_module_set_matches_between_the_two_copies(self) -> None:
        # A narrower module set in one copy is a silent capability difference:
        # a rule that `import`s a missing module simply never matches. Both
        # were measured against the outgoing apt-installed 4.2.3, which linked
        # libmagic and libjansson.
        per_engine = (_PER_ENGINE_DIR / "yara" / "Dockerfile").read_text()
        combined = _ENGINE_RUNNER_DOCKERFILE.read_text()
        for flag in ("--enable-magic", "--enable-cuckoo", "--disable-shared"):
            assert flag in per_engine, f"deploy/engines/yara/Dockerfile lost {flag}"
            assert flag in combined, f"services/engine_runner/Dockerfile lost {flag}"
