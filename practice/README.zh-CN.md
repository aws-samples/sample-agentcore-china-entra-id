# AgentCore 中国区域认证实践材料

先选业务目标，再配置托管能力。已有 MCP 服务或 OpenAPI 的读者可以直接使用自己的接口；只有尚无业务接口时才部署可选库存模板。

| 目标 | 使用的材料 |
|---|---|
| 员工企业登录后查询库存 | 库存工具 schema、客户端请求、配置工作表 |
| 通过 Amazon Quick 查询中国区库存 | Quick MCP 配置说明、现有单应用 OAuth 参数兼容组件 |
| 后台应用使用 IAM 或 Entra 调用库存 | Gateway 调用策略、应用 token 请求、OAuth 出站配置 |
| 员工在企业页面连接下游账号 | 企业 HTTPS 页面、Identity USER_FEDERATION、用户委托部署说明 |
| 后端代表员工调用 Graph /me | Runtime MSAL OBO、应用证书、员工客户端或 Runtime 手动请求 |

## 文件说明

- [可选库存模板](templates/parts-stock-demo.cfn.json)：通过 CloudFormation 上传，创建只读演示 Lambda、执行角色和七天日志组。没有 OAuth 或 JWT 代码。使用独立的 PracticeName；云资源按正常服务用量计费。
- [库存工具定义](schemas/parts-stock-tools.json)：作为 Gateway Lambda target 的完整内联 JSON 数组。
- [Amazon Quick 连接器配置说明](quick-connector-setup.zh-CN.md)：对应第一篇第8节，包含真实配置路径、配套兼容入口的部署方法、工具启用与库存结果确认；明确单应用示例与双应用基础路径的边界。
- [用户委托部署说明](user-delegation-setup.zh-CN.md)：第三篇的页面、Identity、回调绑定和 Runtime MSAL OBO，提供现成程序的部署与员工使用步骤。
- [全球门户与中国区替代方案图解](portal-walkthrough.zh-CN.md)：全球创建入口、中国区员工操作的真实截图，以及实际成功结果示例。
- [Graph OpenAPI 参考](schemas/graph-me.openapi.json)：保留为已有 OpenAPI 集成的接口定义。本篇第三篇使用现成 Runtime 工具，不要求创建 Gateway Graph target。
- [Gateway 调用策略](policies/invoke-gateway.json)：先替换 GATEWAY_ARN，再授予日常调用角色。
- [配置工作表](configuration-worksheet.zh-CN.md)：区分资源 API、员工客户端、后台应用、门户和 Graph 应用。
- [客户端集合](client/agentcore-practice.postman_collection.json)与[空白环境](client/agentcore-practice.postman_environment.json)：21个手动请求，没有脚本，不含真实凭据。

## 客户端使用顺序

1. 在 Postman Import 两个 JSON 文件，选择导入环境，在本地填写本场景字段。
2. “01 员工登录”文件夹在原生 OAuth 2.0 界面选择 Authorization Code with PKCE，填写中国云授权地址、token 地址、client ID、已登记的精确 callback，以及 openid API_URI/agent.invoke。选择 SHA-256；公共客户端不使用 secret。完成登录后 Use Token。
3. IAM 文件夹使用 AWS Signature，service=bedrock-agentcore，region=cn-north-1，填写自己的临时凭据三件套。
4. 应用文件夹先发送 Get application token，将本地响应中的 access token 填入 application_access_token。scope 是实际 API_URI/.default。
5. 每个入口分别 Initialize，记录返回协议版本。仅在服务返回会话 ID 时，填写 mcp_session_id 并启用后续请求中的 Mcp-Session-Id header。
6. 发送 Initialized notification 和 List tools，从响应复制完整工具名，再发送业务请求。切换入口时更新工具名与会话。
7. “05 Runtime OBO Graph”填写 `obo_runtime_url` 与当前获准客户端取得的 `employee_api_access_token`。复制 Runtime 工具名到 `obo_tool_name`，调用参数为 `{}`。没有现成令牌获取客户端时，按用户委托部署说明运行随包提供的员工登录客户端。

库存演示参数为 DEMO-PART-001，返回 DEMO-CN 和数量12。Graph Runtime 工具调用真实 `/me?$select=id`，展示调用状态与是否为同一员工，不输出原始用户资料。用户 OAuth 通过企业 HTTPS 页面完成登录、授权和会话绑定。

中国区域不支持 Consent portal，本材料提供企业应用页面加 Identity 的替代实现。OBO 使用 Runtime 中的 MSAL，不依赖 AgentCore Identity 托管 OBO 或 Gateway Token exchange。

## 实践后的资源管理

保留仍需使用的 Gateway、provider 和应用。结束独立演示环境后，先移除引用库存函数的 target，再通过 CloudFormation 删除该演示栈。删除连接、凭据、权限或 Entra 应用前确认没有其他实践复用。

第三篇的 Runtime、企业授权页面和证书由[用户委托部署说明](user-delegation-setup.zh-CN.md)配置。已有应用可以复用自己的实现；没有实现时直接部署随包示例。其他脚本集成方式见[扩展说明](../extensions/scripted-deployment.zh-CN.md)。
