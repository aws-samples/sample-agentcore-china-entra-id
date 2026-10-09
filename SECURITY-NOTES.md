# Security scope and scanner exceptions

These samples demonstrate authentication using synthetic inventory and a minimal
current-user identity check. A clean static scan is not a production security
certification. Deploy only with the documented Gateway/Runtime authorizers and
review the permissions and data boundary before connecting a real system.

## Hardening covered by regression tests

- The portal serves fixed relative asset and navigation URLs, validates its
  configured HTTPS origin/base path, preserves the API Gateway deployment prefix,
  and checks the request origin and CSRF token for state-changing operations.
- HTTP errors and redirects cannot supply a successful Graph identity result or
  replace an MCP session. Error bodies and bearer tokens are not included in the
  returned diagnostic summaries.
- Certificate credentials use the pinned MSAL version's SHA-256 certificate
  thumbprint support. Private-key matching and certificate validity checks remain
  required. Certificate/key material is not committed.
- The optional inventory template configures bounded concurrency, encrypted logs
  and Lambda environment settings, and scoped log-writing permissions.
- The Graph OpenAPI definition declares its bearer authentication requirement.
  Gateway outbound OAuth configuration is still required; the schema does not
  acquire a token by itself.

## Narrow exceptions

Exceptions are attached to the exact resource, line or historical finding, not
to an entire scanner or source directory.

| Check | Scope and rationale |
| --- | --- |
| Gitleaks `generic-api-key` | The two fingerprints in `.gitleaksignore` refer only to the original commit's `client_id` and `api_app_id` UUIDs in mocked Quick OAuth tests. Current fixtures use obvious synthetic UUIDs. Application identifiers are not credentials. No password, client secret, access token or whole file is excluded. |
| Bandit `B104` | The three MCP server entry points bind `0.0.0.0:8000` inside the AgentCore container as required by the service contract. The configured Runtime authorizer remains mandatory. Do not expose these processes directly as unauthenticated public servers. |
| Semgrep `arbitrary-sleep` | `gateway_oauth.wait_ready` deliberately polls the tracked resource status. It returns only on `READY`, fails on terminal failure, and stops after 30 requests with at most 29 five-second waits. Tests cover success, failure and exhaustion. |
| Checkov `CKV_AWS_116` | The inventory Lambda is invoked synchronously. Lambda asynchronous dead-letter queues do not capture these requests; the caller receives the result or failure. Reassess when adding asynchronous triggers. |
| Checkov `CKV_AWS_117` / cfn-nag `W89` | The inventory handler has no network calls or private resources; it returns in-memory synthetic data. Reassess network isolation when adding real dependencies or data. |
| cfn-nag `W58` | CloudFormation creates the named log group before the function. The role grants `CreateLogStream` and `PutLogEvents` on that group's streams. The generic rule also expects `CreateLogGroup`, which this function does not need. |

The KMS key policy's `Resource: "*"` refers to the key that owns the policy, not
all keys. The account-root statement enables key administration and IAM
delegation; the function role does not receive key-management permissions.
Deploying the inventory template requires permission to create/manage its KMS
key and to let Lambda create the encryption grant, plus five units of available
reserved concurrency. The customer-managed KMS key incurs standard KMS charges.
Deleting the demonstration stack schedules key deletion after seven days; do not
reuse that key for unrelated data.

## Local verification

Install `samples/mcp-auth/requirements.txt` and `pytest` in an isolated environment,
then run from the repository root:

```sh
PYTHONPATH=samples/mcp-auth python -m pytest samples/mcp-auth/tests tests -q
```

The tests use synthetic inputs and mocked service transports. They do not deploy
resources or replace a fresh end-to-end check in the intended AWS and Entra
environment. Secret scanning must include Git history so that the two precise
historical identifier exceptions can be distinguished from new findings.

References:

- [AgentCore MCP container contract](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html)
- [MSAL Python certificate credential API](https://msal-python.readthedocs.io/en/latest/#msal.ClientApplication)
- [Lambda environment encryption and key permissions](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html)
