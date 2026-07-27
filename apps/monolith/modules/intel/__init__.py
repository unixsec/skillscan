"""IOC matching against the local threat_indicator table (coding spec §11.4
INTEL-01/02/03, corrected 2026-07-27 from the previously mislabelled
NET-06/07/08 - see `matcher.py`'s own module docstring). No outbound network
access - matches only against indicators already imported locally
(services/intel-sync, or M6's marketplace sync)."""
