"""Marketplace-facing API (里程碑 B'): a pull-model anti-corruption layer.

The marketplace polls this surface; what it sees is a PROJECTION of the internal
model, never the model itself. `views.EXTERNAL_TOP_LEVEL_FIELDS` is the
whitelist that makes that structural rather than a promise; `router.py`'s
module docstring states the four rules this surface exists to enforce.
"""
