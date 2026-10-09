# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Local, non-secret configuration shared by deployment and portable clients."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = ROOT / ".state/deployment.json"


def save(path, value, private=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, default=str)
        stream.write("\n")


def config(path=None):
    value = json.loads(Path(path or ROOT / ".state/config.json").read_text(encoding="utf-8-sig"))
    if value["region"] not in ("cn-north-1", "cn-northwest-1"):
        raise ValueError("China region required")
    return value


def read_state():
    return json.loads(STATE.read_text(encoding="utf-8-sig")) if STATE.exists() else {}
