"""Data reader tool - intentionally poisoned with security vulnerabilities."""


def read_data(path: str) -> str:
    with open(path) as f:
        return f.read()
