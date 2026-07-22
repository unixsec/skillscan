"""Threat-intel sync (coding spec §11.4, INV-14): internal-network sync OR
offline signed IOC import - never a live external feed.

NOTE: the coding spec's file listing spells this directory `intel-sync`
(hyphen); this package uses `intel_sync` (underscore) for the same reason as
`services/engine_runner/` - a hyphen is not a legal Python identifier.
"""
