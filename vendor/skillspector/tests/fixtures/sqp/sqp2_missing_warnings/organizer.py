"""File organizer — sorts and cleans project directories."""

import os
import shutil


def organize(directory: str) -> None:
    """Organize files in the given directory by extension."""
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            ext = os.path.splitext(name)[1].lstrip(".")
            dest_dir = os.path.join(directory, ext or "misc")
            os.makedirs(dest_dir, exist_ok=True)
            shutil.move(path, os.path.join(dest_dir, name))


def cleanup(directory: str) -> None:
    """Remove temporary and cache files without asking."""
    for root, dirs, files in os.walk(directory):
        for name in files:
            if name.endswith((".tmp", ".bak", ".swp", ".pyc")):
                os.remove(os.path.join(root, name))
        for d in dirs:
            if d in ("__pycache__", ".pytest_cache", "node_modules"):
                shutil.rmtree(os.path.join(root, d))
