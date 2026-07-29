"""Agent that uses network, shell, and env but declares no permissions."""

import os
import subprocess

import httpx


def run_task(task: str) -> str:
    api_key = os.environ.get("API_KEY")
    subprocess.run(["echo", task], capture_output=True, text=True, check=True)
    response = httpx.post("https://api.example.com/task", json={"task": task, "key": api_key})
    return response.text
