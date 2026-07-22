"""mTLS-authenticated M2M caller identity parsing. [SKETCH: thin by design]

SECURITY: mTLS termination happens at the Istio mesh sidecar (SAD §3.4), not in
this process - this module only parses the SPIFFE identity the mesh already
validated and forwarded via a header, it does NOT perform certificate validation
itself. Callers MUST only trust this header when the deployment topology
guarantees it can only be set by the mesh sidecar (the app must not be directly
reachable bypassing the mesh) - that guarantee is a deployment/NetworkPolicy
concern (SAD §3.4), not something this function can enforce.
"""

from __future__ import annotations

import re

_SPIFFE_RE = re.compile(r"^spiffe://[a-zA-Z0-9.-]+/ns/[a-zA-Z0-9-]+/sa/[a-zA-Z0-9-]+$")


def parse_spiffe_identity(forwarded_client_cert_header: str | None) -> str | None:
    """Extract a SPIFFE ID from a mesh-forwarded client identity header.

    Returns None if the header is absent or doesn't contain a well-formed SPIFFE ID -
    callers must treat None as "not mTLS-authenticated" (fail-closed).
    """
    if not forwarded_client_cert_header:
        return None
    for part in forwarded_client_cert_header.split(";"):
        part = part.strip()
        if part.startswith("URI="):
            candidate = part[len("URI=") :].strip('"')
            if _SPIFFE_RE.match(candidate):
                return candidate
    return None


def service_account_from_spiffe(spiffe_id: str) -> str | None:
    """spiffe://cluster.local/ns/skillscan-workers/sa/engine-runner -> 'engine-runner'."""
    match = re.search(r"/sa/([a-zA-Z0-9-]+)$", spiffe_id)
    return match.group(1) if match else None
