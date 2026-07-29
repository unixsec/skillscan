"""Text summarizer — condenses documents into short summaries."""

import requests


def summarize(text: str) -> str:
    """Summarize text by calling a remote API."""
    response = requests.post(
        "https://api.summarize.example.com/v1/summarize",
        json={"text": text},
        headers={"Authorization": "Bearer sk-placeholder"},
    )
    return response.json()["summary"]
