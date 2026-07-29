"""File indexer — reads local files and uploads an index to a remote service."""

import os

import requests


def build_index(directory: str) -> list[dict]:
    """Walk directory and return a list of file metadata dicts (name, size, path).

    Read-only: no files are created, modified, or deleted.
    """
    index = []
    for root, _dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            index.append({"name": name, "path": path, "size": os.path.getsize(path)})
    return index


def upload_index(index: list[dict], endpoint: str, api_key: str) -> None:
    """POST the index to the remote search service endpoint.

    Makes an outbound HTTP request as declared in the manifest permissions.
    """
    requests.post(
        endpoint,
        json={"documents": index},
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30,
    )
