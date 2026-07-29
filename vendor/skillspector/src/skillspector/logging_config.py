# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Central logging configuration for the skillspector package.

Reads ``SKILLSPECTOR_LOG_LEVEL`` directly from the environment (default
``WARNING``) so this module stays cycle-free — it must be importable from
the providers package, which ``constants`` itself depends on.

Use get_logger(__name__) in modules; use Rich console.print() for user-facing output.
"""

from __future__ import annotations

import logging
import os
import sys

SKILLSPECTOR_LOG_LEVEL = os.environ.get("SKILLSPECTOR_LOG_LEVEL", "WARNING")

_PACKAGE_LOGGER_NAME = "skillspector"
_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    root = logging.getLogger(_PACKAGE_LOGGER_NAME)
    root.setLevel(logging.DEBUG)
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(_level_from_string(SKILLSPECTOR_LOG_LEVEL))
        handler.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
        root.addHandler(handler)
    root.setLevel(_level_from_string(SKILLSPECTOR_LOG_LEVEL))
    _configured = True


def _level_from_string(level: str) -> int:
    return getattr(logging, level.upper(), logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the skillspector package namespace."""
    _configure()
    if name.startswith(_PACKAGE_LOGGER_NAME + ".") or name == _PACKAGE_LOGGER_NAME:
        return logging.getLogger(name)
    return logging.getLogger(f"{_PACKAGE_LOGGER_NAME}.{name}")


def set_level(level: int | str) -> None:
    """Set the package root logger and its handler level (e.g. for CLI --verbose)."""
    _configure()
    lvl = level if isinstance(level, int) else _level_from_string(level)
    root = logging.getLogger(_PACKAGE_LOGGER_NAME)
    root.setLevel(lvl)
    for h in root.handlers:
        h.setLevel(lvl)
