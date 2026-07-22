"""LLMPort (coding spec §6) - a direct LLM-calling abstraction meant to live in
the sandbox (engine-runner); endpoint injected via config, defaulting to an
internal vLLM instance; content is data only, output is findings-shaped only.

HONEST STATUS: no implementation of this exact shape exists in this codebase.
The closest thing is `services/engine_runner/adapters/skillspector.py`, which
invokes the vendored skillspector CLI as a subprocess and passes
`OPENAI_BASE_URL` as an environment variable for THAT TOOL to call an LLM
internally - this is an indirect, subprocess-boundary integration (the
adapter itself implements `DetectionEnginePort.analyze(files: dict[str,
bytes], ...)`, per §10's subprocess-adapter contract), not a direct
`LLMPort.analyze(content: bytes, *, prompt_version, deadline) -> EngineResult`
call. No code in this repository calls an LLM endpoint directly in this
Protocol's shape - flagging this honestly rather than forcing a superficial
retrofit of the skillspector adapter, which would misrepresent what it
actually does."""

from __future__ import annotations

from typing import Protocol

from skillscan_core import EngineResult


class LLMPort(Protocol):
    # SECURITY: endpoint injected via config, defaults to internal vLLM;
    # content is data only; output must be findings-shaped only (never
    # free-form text fed back into a decision path).
    async def analyze(
        self, content: bytes, *, prompt_version: str, deadline: float | None
    ) -> EngineResult: ...
