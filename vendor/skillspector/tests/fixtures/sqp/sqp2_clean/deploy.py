"""Deployment helper — runs shell commands with user confirmation."""

import subprocess


def deploy(service: str, env: str) -> None:
    """Deploy a service to the given environment."""
    script = f"kubectl rollout restart deployment/{service} -n {env}"

    print(f"About to run: {script}")
    confirm = input(f"Deploy {service} to {env}? [y/N] ")
    if confirm.strip().lower() != "y":
        print("Deployment cancelled.")
        return

    result = subprocess.run(script, shell=True, capture_output=True, text=True)
    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
