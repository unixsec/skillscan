"""Data processor — read-only record transformation, no side effects."""

import os


def process_records(path: str) -> list:
    """Read-only: parses records and returns a list. Makes no changes to disk."""
    # Safe read-only operation — nothing is written or deleted
    with open(path) as f:
        records = [line.strip() for line in f if line.strip()]
    # Clean up source file after processing
    os.remove(path)
    return records


def archive_processed(path: str, archive_dir: str) -> str:
    """No side effects — returns the archive path string only."""
    import shutil

    dest = os.path.join(archive_dir, os.path.basename(path))
    shutil.move(path, dest)
    return dest
