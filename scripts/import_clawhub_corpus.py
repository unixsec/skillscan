#!/usr/bin/env python3
"""Download a real-world skill-package corpus from clawhub.ai or skillhub.cn for
skillscan functional/load testing, saving each package's zip as served and also a
transcoded tar (see UPDATE 2026-07-30 below for which of the two to upload).

The FILENAME is historical: `--source clawhub` was the only source until
2026-07-30, and the module is referenced by name from
`services/engine_runner/normalizer.py`. It now serves both markets - see SOURCES.

WHY THIS SCRIPT EXISTS. clawhub.ai bulk-import test rounds have happened
roughly four times in this project's history (see docs/stories/BACKLOG.md,
the 2026-07-08 100-skill round and the 2026-07-22/23 481/884-skill rounds) and
every prior round rebuilt this tooling from scratch and threw it away
afterwards. This is the first round that commits it, so a future round can
just re-run it.

SOURCES. `--source clawhub` (default) and `--source skillhub`. Everything except
discovery and the download URL is shared: the zip->tar transcode, the resume
check, the pacing, the retry/backoff and the summary are all source-agnostic.

  clawhub   clawhub.ai. One JSON feed snapshot, no pagination - see DISCOVERY.
  skillhub  api.skillhub.cn, a Chinese MIRROR of clawhub (every record measured
            2026-07-30 carried `"source": "clawhub"` and an `upstream_url` on
            clawhub.ai). VERIFIED LIVE 2026-07-30, no auth on either call:
              listing   GET /api/skills?page=N&pageSize=100&keyword=&category=
                        -> {"code":0,"data":{"skills":[...],"total":97723}}
              download  GET /api/v1/download?slug=X[&namespace=&version=]
                        -> 302 -> https://skillhub-*.cos.accelerate.myqcloud.com/
                                  skills/<slug>/<version>.zip   (application/zip)
            PAGINATED, which is the one genuine difference from clawhub's single
            snapshot: `total` is ~97.7k, so this walks pages until it has enough
            candidates rather than reading one document.
            Skill ids are taken as the CANONICAL `namespace.canonicalName`
            (`@handle/slug`), not the bare slug: at ~97.7k skills bare slugs
            collide, and a colliding bare slug is exactly what produced clawhub's
            `409 ambiguous slug` class. (The download endpoint answers on the bare
            slug alone - measured - but `namespace`/`version` are sent anyway so
            the request names one specific artifact.)
            No robots.txt and no sitemap (SPA catch-all), so there are no crawl
            rules to honour here; the pacing below is applied regardless, because
            this is a functional test of skillscan and not a load test of a third
            party.

DISCOVERY. clawhub.ai's own robots.txt (fetched live, 2026-07-29) disallows
`/api/` for all crawlers but explicitly carves out two exceptions:
`/v1/feeds/plugins` and `/v1/feeds/skills`. This script therefore discovers
candidates from `GET /v1/feeds/skills` - a single JSON snapshot (no auth, no
pagination token; ~800 entries measured 2026-07-29) - rather than the
`/api/v1/skills` cursor-paginated listing earlier rounds used, which robots.txt
now disallows. Being a polite citizen toward a third-party site also means:
default pacing between requests (see --pace-seconds), retry-with-backoff on
HTTP 429 honoring Retry-After, and no attempt to enumerate beyond what the one
feed snapshot already offers.

Each feed entry's `id` looks like "@publisher/skill-name" and its
`install.candidates[0]` names a `sourceRef`:
  - "public-clawhub": natively hosted here - `GET /api/v1/download?slug=X`
    (X = the id's slug after the publisher scope, e.g.
    "@alipay/alipay-authenticate-wallet" -> "alipay-authenticate-wallet")
    reliably returns a real zip. Confirmed live, 2026-07-29.
  - "public-github": a GitHub-imported skill. The SAME download endpoint
    returns a 200 with a JSON "handoff" object (sourceRef/repo/commit/
    archiveUrl) instead of a zip - not a failure, just a different kind of
    result this script does not follow (out of scope, same choice every
    prior round made; the corpus is large enough from public-clawhub alone).
  - Historically ~5% of slugs still 409 ("ambiguous slug" - clawhub's own
    response when a bare slug collides across publishers, not a bug in
    anything here). Pre-filtering to sourceRef=="public-clawhub" avoids most
    of that, but this script still treats any non-2xx or non-zip response as
    a recorded, non-fatal failure and moves on.

INGEST BOUNDARY. `unpack_hardened` (services/engine_runner/normalizer.py) still
accepts tar only - it is a hardened parser boundary and deliberately grew no zip
branch. This script transcodes zip -> tar itself, outside that boundary, in
throwaway test tooling. Symlink/hardlink zip members are dropped (not converted)
during transcoding: unpack_hardened rejects the WHOLE archive on any
symlink/hardlink member by design (a link target is attacker-controlled data
with no legitimate place in a canonical content-hashed file set), so silently
carrying one through would only trade a clean, visible skip here for an opaque
whole-package rejection later.

UPDATE 2026-07-30: the PRODUCT now accepts zip uploads directly, via
`normalizer.unpack_package_archive` - a bounded transcode layer in front of
`unpack_hardened`, with the resource bounds this script's version lacks (entry
count, per-file and total uncompressed size, compression ratio, encrypted
entries, spanned archives). This script's own transcode is kept as-is so its
bare-`python3` invocation below needs nothing installed; a real verification
round should upload the .zip it saves, not the .tar, since the zip path is now
the one under test.

IDEMPOTENT / RESUMABLE. Safe to re-run: a candidate whose <out-dir>/<key>/ already
holds both the .zip and the .tar is skipped without a network request. `key` is a
filesystem-safe name derived from the candidate (the bare slug for clawhub, which
keeps existing corpora on disk valid; `<handle>__<slug>` for skillhub, whose ids
carry a `/`). No project-internal secret is needed - this script only ever talks
to the market it was pointed at.

Usage:
    python3 scripts/import_clawhub_corpus.py --out-dir /path/to/corpus
    python3 scripts/import_clawhub_corpus.py --out-dir ./corpus --target-count 220
    python3 scripts/import_clawhub_corpus.py --source skillhub --out-dir ./sh --target-count 55
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any

CLAWHUB_FEED_URL = "https://clawhub.ai/v1/feeds/skills"
CLAWHUB_DOWNLOAD_URL = "https://clawhub.ai/api/v1/download"
SKILLHUB_LISTING_URL = "https://api.skillhub.cn/api/skills"
SKILLHUB_DOWNLOAD_URL = "https://api.skillhub.cn/api/v1/download"
SKILLHUB_PAGE_SIZE = 100
# A guard on the pagination loop, not a corpus limit: `total` is ~97.7k, so a
# discover() that kept asking for pages until it had `target_count` usable
# candidates could otherwise walk ~977 pages if the filter rejected everything.
SKILLHUB_MAX_PAGES = 40
USER_AGENT = (
    "skillscan-corpus-import/1.0 (+security testing tool; "
    "see scripts/import_clawhub_corpus.py in the skillscan repo)"
)
DEFAULT_TARGET_COUNT = 220
DEFAULT_PACE_S = 0.4
MAX_RETRIES = 4
ZIP_MAGIC_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


class FetchError(RuntimeError):
    """Any non-recoverable HTTP/network failure fetching a single URL."""


def _http_get(url: str, *, timeout: int = 30) -> tuple[bytes, dict[str, str], int]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https host
                return resp.read(), {k.lower(): v for k, v in resp.headers.items()}, resp.status
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < MAX_RETRIES:
                retry_after_raw = exc.headers.get("Retry-After", "2") if exc.headers else "2"
                try:
                    retry_after = int(retry_after_raw)
                except ValueError:
                    retry_after = 2
                print(
                    f"    [rate-limited] sleeping {retry_after}s (attempt {attempt}/{MAX_RETRIES})",
                    file=sys.stderr,
                )
                time.sleep(retry_after)
                continue
            body = exc.read()[:300] if exc.fp is not None else b""
            raise FetchError(f"HTTP {exc.code} fetching {url}: {body!r}") from exc
        except (urllib.error.URLError, OSError) as exc:
            # BUG (found live, 2026-07-29, mid-run of a real 220-package
            # download): a bare socket-level read timeout on clawhub's own
            # connection surfaces as a plain `TimeoutError` (an `OSError`
            # subclass), NOT wrapped in `urllib.error.URLError` the way a
            # connect-time failure is - `urlopen` only wraps errors raised
            # while ESTABLISHING the connection, not ones raised while reading
            # the response after it's already open. Catching only URLError let
            # one slow/dropped response crash the whole script 200/220
            # packages in, with nothing retried. Catching `OSError` too closes
            # that actual gap rather than broadening for its own sake.
            last_exc = exc
            time.sleep(1.5 * attempt)
    raise FetchError(f"failed after {MAX_RETRIES} retries fetching {url}: {last_exc}")


@dataclass(frozen=True)
class Candidate:
    """One discovered package, in the shape the download half needs.

    `id` is the CANONICAL skill id (`@handle/slug`) - what a skillscan submission
    should register as its `skill_id`, and the only form that is unambiguous
    across publishers. `slug` is the bare slug the download endpoints key on.
    `key` is the on-disk directory name (see `_safe_key`).
    """

    id: str
    slug: str
    key: str
    title: str = ""
    version: str = ""
    namespace: str = ""


_UNSAFE_KEY_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_key(raw: str) -> str:
    """A filesystem-safe directory name for one candidate.

    The input is third-party feed data used to build a path under `--out-dir`, so
    every character outside `[A-Za-z0-9._-]` collapses to `_` and any leading `.`
    is stripped: that removes `/`, `\\`, NUL and `..` in one pass rather than
    blacklisting traversal shapes one at a time. Returns "" when nothing usable
    is left, which callers treat as "skip this candidate".
    """
    collapsed = _UNSAFE_KEY_CHARS.sub("_", raw.strip()).lstrip(".")
    return collapsed[:120]


def discover_clawhub(limit: int | None = None) -> list[Candidate]:
    """GET the robots.txt-permitted /v1/feeds/skills snapshot and return only
    entries whose first install candidate is sourceRef "public-clawhub"
    (natively hosted -> a direct zip download), in feed order.

    `key` is the bare slug, unchanged from before this script grew a `--source`
    seam, so an existing clawhub corpus on disk still resumes rather than being
    re-downloaded under new directory names.
    """
    body, _headers, _status = _http_get(CLAWHUB_FEED_URL)
    data = json.loads(body)
    entries = data.get("entries", [])
    candidates: list[Candidate] = []
    for entry in entries:
        if entry.get("type") != "skill":
            continue
        install_candidates = (entry.get("install") or {}).get("candidates") or []
        if not install_candidates:
            continue
        if install_candidates[0].get("sourceRef") != "public-clawhub":
            continue
        skill_id = entry.get("id", "")
        if "/" not in skill_id:
            continue
        slug = skill_id.rsplit("/", 1)[-1]
        key = _safe_key(slug)
        if not slug or not key:
            continue
        candidates.append(Candidate(id=skill_id, slug=slug, key=key, title=entry.get("title", "")))
    if limit is not None:
        candidates = candidates[:limit]
    return candidates


def discover_skillhub(limit: int | None = None) -> list[Candidate]:
    """Walk `GET /api/skills?page=N&pageSize=100` until `limit` candidates are
    collected, the pages run out, or SKILLHUB_MAX_PAGES is reached.

    This is the one place the two sources genuinely differ: clawhub publishes a
    single feed snapshot, skillhub has ~97.7k skills behind a paginated listing.
    The id taken is `namespace.canonicalName` (`@handle/slug`), never the bare
    slug - see the module docstring.
    """
    candidates: list[Candidate] = []
    seen: set[str] = set()
    want = limit if limit is not None else DEFAULT_TARGET_COUNT
    for page in range(1, SKILLHUB_MAX_PAGES + 1):
        query = urllib.parse.urlencode(
            {"page": page, "pageSize": SKILLHUB_PAGE_SIZE, "keyword": "", "category": ""}
        )
        body, _headers, _status = _http_get(f"{SKILLHUB_LISTING_URL}?{query}")
        payload = json.loads(body)
        if payload.get("code") != 0:
            raise FetchError(f"skillhub listing page {page} returned code={payload.get('code')!r}")
        data = payload.get("data") or {}
        skills = data.get("skills") or []
        if not skills:
            break
        for record in skills:
            slug = str(record.get("slug") or "")
            namespace = record.get("namespace") or {}
            canonical = str(namespace.get("canonicalName") or "")
            handle = str(namespace.get("handle") or "")
            if not slug or not canonical:
                continue
            if canonical in seen:
                continue
            key = _safe_key(f"{handle}__{slug}" if handle else slug)
            if not key:
                continue
            seen.add(canonical)
            candidates.append(
                Candidate(
                    id=canonical,
                    slug=slug,
                    key=key,
                    title=str(record.get("name") or ""),
                    version=str(record.get("version") or ""),
                    namespace=handle,
                )
            )
            if len(candidates) >= want:
                return candidates
        if len(skills) < SKILLHUB_PAGE_SIZE:
            break
        # One listing page is a request like any other - paced the same way.
        time.sleep(DEFAULT_PACE_S)
    return candidates


def _clawhub_download_url(candidate: Candidate) -> str:
    return f"{CLAWHUB_DOWNLOAD_URL}?slug={urllib.parse.quote(candidate.slug, safe='')}"


def _skillhub_download_url(candidate: Candidate) -> str:
    params: dict[str, str] = {"slug": candidate.slug}
    # MEASURED 2026-07-30: the endpoint answers on `slug` alone and resolves to
    # `skills/<slug>/<version>.zip`. Sending the two optional parameters when the
    # listing gave them names one specific artifact instead of relying on that.
    if candidate.namespace:
        params["namespace"] = candidate.namespace
    if candidate.version:
        params["version"] = candidate.version
    return f"{SKILLHUB_DOWNLOAD_URL}?{urllib.parse.urlencode(params)}"


@dataclass(frozen=True)
class Source:
    """A market this script can import from: how to list it, how to fetch one
    package from it, and what to print while doing so."""

    name: str
    listing_url: str
    discover: Callable[[int | None], list[Candidate]]
    download_url: Callable[[Candidate], str]


SOURCES: dict[str, Source] = {
    "clawhub": Source(
        name="clawhub",
        listing_url=CLAWHUB_FEED_URL,
        discover=discover_clawhub,
        download_url=_clawhub_download_url,
    ),
    "skillhub": Source(
        name="skillhub",
        listing_url=SKILLHUB_LISTING_URL,
        discover=discover_skillhub,
        download_url=_skillhub_download_url,
    ),
}


@dataclass
class DownloadResult:
    slug: str
    ok: bool
    reason: str = ""
    zip_bytes: int = 0
    tar_bytes: int = 0
    symlinks_skipped: list[str] = field(default_factory=list)
    already_had: bool = False
    skill_id: str = ""


def zip_bytes_to_tar_bytes(zip_bytes: bytes) -> tuple[bytes, list[str]]:
    """Transcode a zip archive to a POSIX tar. A plain container transcode for
    corpus prep, done entirely outside skillscan's ingest boundary. Returns
    (tar_bytes, dropped_symlink_names).

    NOTE (2026-07-30): this deliberately still DROPS symlink members, while the
    product's ingest transcoder (`normalizer.zip_to_tar_bytes`) now REJECTS the
    whole archive on one. The divergence is intentional - this is a test-corpus
    tool, not a security boundary, and its output goes on to face the real
    boundary anyway. Do not cite `symlinks_skipped` as evidence about real
    packages: it has been empty in every recorded import run, and a sweep of
    364 real packages across both marketplaces found zero non-regular members.
    An earlier version of the ingest transcoder dropped symlinks on the
    strength of that field appearing to mean the opposite."""
    skipped: list[str] = []
    tar_buf = BytesIO()
    with (
        zipfile.ZipFile(BytesIO(zip_bytes)) as zf,
        tarfile.open(fileobj=tar_buf, mode="w") as tf,
    ):
        for info in zf.infolist():
            if info.is_dir():
                continue
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if unix_mode and stat.S_ISLNK(unix_mode):
                skipped.append(info.filename)
                continue
            data = zf.read(info)
            tarinfo = tarfile.TarInfo(name=info.filename)
            tarinfo.size = len(data)
            mode = unix_mode & 0o777
            tarinfo.mode = mode if mode else 0o644
            try:
                tarinfo.mtime = int(time.mktime((*info.date_time, 0, 0, -1)))
            except (OverflowError, ValueError):
                tarinfo.mtime = 0
            tf.addfile(tarinfo, BytesIO(data))
    return tar_buf.getvalue(), skipped


def download_one(candidate: Candidate, out_dir: Path, *, source: Source) -> DownloadResult:
    skill_dir = out_dir / candidate.key
    zip_path = skill_dir / f"{candidate.key}.zip"
    tar_path = skill_dir / f"{candidate.key}.tar"
    # The canonical `@handle/slug` id, written next to the artifacts: it is what a
    # skillscan submission must send as `skill_id`, and it cannot be recovered
    # from the directory name (which flattened the `/`).
    id_path = skill_dir / "skill_id.txt"
    if zip_path.exists() and tar_path.exists():
        if not id_path.exists():
            skill_dir.mkdir(parents=True, exist_ok=True)
            id_path.write_text(f"{candidate.id}\n")
        return DownloadResult(
            slug=candidate.slug,
            skill_id=candidate.id,
            ok=True,
            already_had=True,
            zip_bytes=zip_path.stat().st_size,
            tar_bytes=tar_path.stat().st_size,
        )

    try:
        body, headers, _status = _http_get(source.download_url(candidate))
    except FetchError as exc:
        return DownloadResult(slug=candidate.slug, skill_id=candidate.id, ok=False, reason=str(exc))

    content_type = headers.get("content-type", "")
    if not body.startswith(ZIP_MAGIC_PREFIXES):
        reason = (
            f"non-zip response (content-type={content_type!r}, likely a "
            "GitHub-handoff JSON object or an error page)"
        )
        return DownloadResult(slug=candidate.slug, skill_id=candidate.id, ok=False, reason=reason)

    try:
        tar_bytes, skipped = zip_bytes_to_tar_bytes(body)
    except zipfile.BadZipFile as exc:
        return DownloadResult(
            slug=candidate.slug, skill_id=candidate.id, ok=False, reason=f"bad zip: {exc}"
        )
    if not tar_bytes:
        return DownloadResult(
            slug=candidate.slug,
            skill_id=candidate.id,
            ok=False,
            reason="zip contained no regular files to transcode",
        )

    skill_dir.mkdir(parents=True, exist_ok=True)
    zip_path.write_bytes(body)
    tar_path.write_bytes(tar_bytes)
    id_path.write_text(f"{candidate.id}\n")
    return DownloadResult(
        slug=candidate.slug,
        skill_id=candidate.id,
        ok=True,
        zip_bytes=len(body),
        tar_bytes=len(tar_bytes),
        symlinks_skipped=skipped,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--source",
        choices=sorted(SOURCES),
        default="clawhub",
        help="Which market to import from (default clawhub) - see the module docstring.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Directory to hold one subdirectory per skill (each with its .zip and .tar).",
    )
    parser.add_argument(
        "--target-count",
        type=int,
        default=DEFAULT_TARGET_COUNT,
        help=f"How many public-clawhub candidates to attempt (default {DEFAULT_TARGET_COUNT}).",
    )
    parser.add_argument(
        "--pace-seconds",
        type=float,
        default=DEFAULT_PACE_S,
        help=f"Sleep between download requests (default {DEFAULT_PACE_S}s) - be a polite citizen.",
    )
    args = parser.parse_args()

    source = SOURCES[args.source]
    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] discovering candidates from {source.listing_url} ...", file=sys.stderr)
    try:
        candidates = source.discover(args.target_count)
    except (FetchError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not discover candidates on {source.name}: {exc}", file=sys.stderr)
        return 1
    print(
        f"[*] {len(candidates)} {source.name} candidates (target {args.target_count})",
        file=sys.stderr,
    )

    results: list[DownloadResult] = []
    for i, cand in enumerate(candidates, 1):
        slug = cand.key
        result = download_one(cand, out_dir, source=source)
        results.append(result)
        if result.already_had:
            status = "already have"
        elif result.ok:
            suffix = (
                f", {len(result.symlinks_skipped)} symlink(s) dropped)"
                if result.symlinks_skipped
                else ")"
            )
            status = f"OK ({result.zip_bytes}B zip -> {result.tar_bytes}B tar" + suffix
        else:
            status = f"FAIL ({result.reason})"
        print(f"[{i}/{len(candidates)}] {slug}: {status}", file=sys.stderr, flush=True)
        if not result.already_had:
            time.sleep(args.pace_seconds)

    ok_results = [r for r in results if r.ok]
    failed_results = [r for r in results if not r.ok]
    all_symlinks_skipped = {r.slug: r.symlinks_skipped for r in ok_results if r.symlinks_skipped}

    summary: dict[str, Any] = {
        "source": source.name,
        "target_count": args.target_count,
        "candidates_considered": len(candidates),
        "downloaded_ok": len(ok_results),
        "already_had": sum(1 for r in ok_results if r.already_had),
        "failed": len(failed_results),
        "symlinks_skipped_by_slug": all_symlinks_skipped,
        "skill_ids_by_slug": {r.slug: r.skill_id for r in ok_results if r.skill_id},
        "failures": [{"slug": r.slug, "reason": r.reason} for r in failed_results],
    }
    summary_path = out_dir / "import_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(
        f"[*] done: {len(ok_results)} ok ({summary['already_had']} already present), "
        f"{len(failed_results)} failed. summary -> {summary_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
