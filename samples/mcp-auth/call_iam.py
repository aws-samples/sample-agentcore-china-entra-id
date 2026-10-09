# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Call the IAM Gateway with the standard AWS credential chain."""
import json
import boto3
from client import exercise
from local_config import config, read_state

cfg = config()
aws = boto3.Session(region_name=cfg["region"])
rows = exercise(
    read_state()["gateways"]["iam"]["url"],
    region=cfg["region"],
    credentials=aws.get_credentials().get_frozen_credentials(),
)
print(json.dumps(rows, ensure_ascii=False, indent=2))
