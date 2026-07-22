"""The sandboxed engine-runner worker's own code (coding spec §11.4/§11.5:
normalizer, in-house detectors, adapters). Deployed as its own container in
production (gVisor-sandboxed, per M7's IaC) - distinct from `apps/monolith`.

NOTE: the coding spec's file listing spells this directory `engine-runner`
(hyphen), matching its intended container/deployment-artifact name. A hyphen
is not a legal Python identifier, so this package uses `engine_runner`
(underscore) instead - the only deviation from the spec's literal path in this
module, made for Python import mechanics, not a design change.
"""
