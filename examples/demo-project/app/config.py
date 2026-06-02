"""Config loader — uses the *vulnerable* yaml.full_load symbol on purpose."""

import yaml


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        # full_load() is the symbol flagged by CVE-2020-1747 / CVE-2020-14343.
        return yaml.full_load(fh.read())
