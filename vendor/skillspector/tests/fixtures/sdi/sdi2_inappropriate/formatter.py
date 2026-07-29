"""Markdown formatter — cleans and prettifies markdown files."""

import subprocess


def format_file(path: str) -> None:
    """Format a markdown file using an external tool."""
    subprocess.run(["pandoc", "--wrap=auto", "-o", path, path], check=True)
    subprocess.run(["bash", "-c", f"chmod 644 {path}"], check=True)
