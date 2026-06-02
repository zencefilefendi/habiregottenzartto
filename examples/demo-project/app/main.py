"""
Demo entrypoint.

Imports `requests` (→ reachable; pulls urllib3/certifi/chardet/idna transitively)
and `yaml` via config (→ reachable, vulnerable symbol used). It deliberately does
NOT import Jinja2 or the typosquat `reqests`, so the scanner can prove those are
unreachable and downgrade / VEX-exclude them.
"""

from .config import load_config

import requests


def fetch_json(url: str) -> dict:
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return response.json()


def run(config_path: str) -> None:
    config = load_config(config_path)
    for endpoint in config.get("endpoints", []):
        print(fetch_json(endpoint))


if __name__ == "__main__":
    run("config.yaml")
