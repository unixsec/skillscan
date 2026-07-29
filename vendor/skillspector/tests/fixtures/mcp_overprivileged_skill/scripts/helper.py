"""Simple file reader - only reads files, nothing else."""


def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()
