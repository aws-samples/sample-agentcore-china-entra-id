# AgentCore 与世纪互联 Entra ID 实践材料

本仓库围绕三项接入任务提供配置材料：员工登录后使用工具、后台应用调用工具、工具代表员工访问 Microsoft Graph。先从[实践材料](practice/README.zh-CN.md)开始。前两篇以 Entra 与 Gateway 控制台配置为主，第三篇提供企业授权页面和 Runtime 用户委托的现成实现。

配套包含可选演示库存模板、Lambda 工具 schema、Graph OpenAPI 参考、IAM 策略、配置工作表，以及21个现成客户端手动请求。演示库存使用合成数据；Graph Runtime 工具调用真实 /me，并展示调用状态与同一用户匹配结果。

中国区域不支持 Consent portal。第三篇使用[企业 HTTPS 页面加 Identity USER_FEDERATION](practice/user-delegation-setup.zh-CN.md)作为替代，并使用 Runtime 中的 MSAL 执行 Entra OBO。已有应用可集成同样的调用；没有应用时直接部署配套示例，无需从头编写授权代码。

- [控制台材料与使用顺序](practice/README.zh-CN.md)
- [第三篇用户委托部署说明](practice/user-delegation-setup.zh-CN.md)
- [全球托管门户与中国区替代方案图解](practice/portal-walkthrough.zh-CN.md)
- [历史脚本部署与自定义集成](extensions/scripted-deployment.zh-CN.md)
- [旧版手动请求材料](manual-validation/README.zh-CN.md)

客户端、账号和凭据均由读者自己的环境提供。仓库不含已部署环境配置、密钥、员工 token 或运行报告。
