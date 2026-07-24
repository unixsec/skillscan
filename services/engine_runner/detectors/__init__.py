"""In-house zero-coverage detectors (coding spec §11.4, SRS Appendix A):
DATA-06 (pii.py), FILE-06 (file_type.py), CODE-12 (crypto_weak.py),
FILE-04 (toctou.py).

SUP-06 (provenance.py, publisher-provenance/signature attestation) was
removed 2026-07-24: in this deployment `ProvenanceDetector` was never
constructed with a trust anchor, so it could only ever surface
"missing manifest" (near-universal - essentially no real-world skill ships
a signed PROVENANCE.json yet) or "unverifiable, no trust anchor configured" -
never a genuine signature failure. It provided no discriminating security
signal in practice."""
