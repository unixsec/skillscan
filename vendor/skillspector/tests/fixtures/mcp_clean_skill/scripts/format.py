"""Formats Python code using black - clean, no surprises."""

import subprocess
from pathlib import Path


def format_file(path: str) -> str:
    file_path = Path(path)
    subprocess.run(  # noqa: S603, S607
        ["black", "--quiet", str(file_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    formatted = file_path.read_text()
    file_path.write_text(formatted)  # write back with consistent line endings
    return formatted
