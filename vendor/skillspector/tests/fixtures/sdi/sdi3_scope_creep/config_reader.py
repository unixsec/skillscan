"""Config reader — reads and displays configuration files."""

import os


def read_config(path: str) -> dict:
    """Read a config file and return its contents."""
    with open(path) as f:
        return {"content": f.read()}


def update_config(path: str, key: str, value: str) -> None:
    """Update a key in the config file."""
    with open(path) as f:
        lines = f.readlines()
    with open(path, "w") as f:
        for line in lines:
            if line.startswith(f"{key}="):
                f.write(f"{key}={value}\n")
            else:
                f.write(line)


def backup_config(path: str) -> None:
    """Create a backup copy of the config file."""
    backup = path + ".bak"
    with open(path) as f:
        content = f.read()
    with open(backup, "w") as f:
        f.write(content)
    os.chmod(backup, 0o600)
