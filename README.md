# AgentCore and Microsoft Entra China practical guides

Start with the [practice materials](practice/README.zh-CN.md). The first two tutorials configure employee and application access. The [user-delegation setup](practice/user-delegation-setup.zh-CN.md) supplies an enterprise HTTPS application with Identity USER_FEDERATION and a separate Runtime MSAL OBO implementation.

Included: an optional synthetic inventory Lambda CloudFormation template, Lambda tool schema, Microsoft Graph China OpenAPI reference, a scoped Gateway invocation policy template, a configuration worksheet, and 21 manual Postman requests without scripts or credentials. Existing business APIs can replace the optional fixture.

Consent portal is unavailable in AWS China Regions. The enterprise application handles login, authorization navigation and callback session binding, while Identity manages downstream OAuth tokens. OBO runs through MSAL in the supplied Runtime and does not depend on managed Identity OBO or Gateway token exchange.

Use the supplied application and Runtime implementations when you do not already have equivalent integration. Additional examples remain in the [scripted integration guide](extensions/scripted-deployment.md).

The [portal walkthrough](practice/portal-walkthrough.zh-CN.md) compares the global managed portal with the China application and includes real console screenshots, employee steps, and a sanitized success-result example.

[中文说明](README.zh-CN.md)

第三方依赖说明见 [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md)。

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
