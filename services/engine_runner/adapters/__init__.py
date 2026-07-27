"""Vendored OSS engine adapters (coding spec §10, §10A): bandit.py, osv.py,
yara.py, skillspector.py, aig.py.

SECURITY (INV-15): every adapter drives its engine as an arm's-length
`subprocess` (`shell=False`) and this package never imports vendored engine
code - that separation is what keeps the copyleft/licence boundary intact and
is asserted by the licence gate in `.ci/pipeline.yml`. Shared subprocess
plumbing (absolute-deadline handling, timeout/parse failures mapping to
`EngineStatus.ERROR|TIMEOUT` rather than a silent "0 findings") lives in
`base.py`.

This file exists so the directory is a regular package rather than a PEP 420
namespace package - `from engine_runner.adapters import yara` is unresolvable
for a type checker otherwise, matching how the sibling `detectors` package is
already laid out. It deliberately re-exports nothing: importers name the
submodule they need.
"""
