> Extended scripted deployment reference. Start with [the console practice materials](../practice/README.zh-CN.md) for the current tutorials. Article 3 uses the [China user-delegation deployment guide](../practice/user-delegation-setup.zh-CN.md) for the supplied HTTPS application and Runtime MSAL OBO implementations.

# AgentCore China and Microsoft Entra ID authentication samples

This repository contains runnable reference code for Amazon Bedrock AgentCore Runtime, Gateway, and Identity in AWS China, integrated with Microsoft Entra ID operated by 21Vianet.

See [中文使用说明](scripted-deployment.zh-CN.md) for configuration, deployment, browser login, expected results, and cleanup.

For independent checks with an existing client, use the [manual validation materials](../manual-validation/README.zh-CN.md). They include 29 Postman HTTP requests and a blank environment template, with no pre-request scripts, test scripts, or credentials. These templates have been checked locally; they are not evidence of a completed Postman run or production business validation.

The samples cover employee authorization code with PKCE, AWS IAM request signing, application client credentials using a secret or certificate, Identity M2M, Gateway OAuth M2M outbound authentication, Identity user OAuth with a session-bound web callback, certificate-based Entra OBO in Runtime, and an Amazon Quick Cloud Connector integration.

Use your own AWS China account, private deployment bucket, Entra tenant, application registration, and credentials. Configuration templates are included; credentials, deployed resource addresses, and real execution records are not distributed.

The included walkthrough uses one existing Entra application as both client and resource API. The Quick OAuth parameter adapter is specific to that setup and to the configured Quick callback. These are sample conventions, not required product-wide architecture.

The MCP tools return synthetic maintenance and inventory data. The delegated identity examples use China Microsoft Graph `User.Read` to verify the signed-in identity; they do not grant mailbox, file, or business record access.

This is a reference implementation, not a managed service or a claim that every OAuth flow or regional feature has been validated.
