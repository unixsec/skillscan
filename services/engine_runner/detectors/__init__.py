"""In-house zero-coverage detectors (coding spec §11.4, SRS Appendix A):
CRED-06 (pii.py), FILE-01/FILE-02 (file_type.py), CODE-10 (crypto_weak.py),
FILE-06 (toctou.py). (2026-07-27: corrected from the previously mislabelled
DATA-06/FILE-06/CODE-12/FILE-04 - see each module's own docstring/D7 note.)

SUP-06 (provenance.py, publisher-provenance/signature attestation) was
removed 2026-07-24: in this deployment `ProvenanceDetector` was never
constructed with a trust anchor, so it could only ever surface
"missing manifest" (near-universal - essentially no real-world skill ships
a signed PROVENANCE.json yet) or "unverifiable, no trust anchor configured" -
never a genuine signature failure. It provided no discriminating security
signal in practice."""
