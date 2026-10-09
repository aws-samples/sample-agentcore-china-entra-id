# 使用现成客户端手动验收

本目录包含 Postman HTTP 请求集合与空白环境模板。没有预请求脚本、测试脚本、自动获取凭据或自动判定通过的逻辑。
这些材料是操作模板，已经检查 JSON 结构、变量与请求顺序；尚不能作为该 Postman 客户端在你的环境中实测成功的证据。

## 准备

1. 使用组织允许的 Postman 环境，Import 两个 JSON 文件，选择导入的环境。
2. 从已部署资源读取实际 URL。`user_gateway_url`、`app_gateway_url`、`iam_gateway_url` 分别来自 `.state/deployment.json` 的 `gateways.jwt.url`、`gateways.app.url`、`gateways.iam.url`。`oauth_gateway_url` 来自 `.state/gateway-oauth-deployment.json` 的 `url`；其受限调用角色要获准访问该文件 `arn` 指定的 Gateway。`obo_runtime_url` 完整复制自 `.state/cloud-obo-deployment.json` 的 `runtime.url`，保留 ARN 编码及查询参数，不能使用裸 ARN，也不能把它替换成第一篇 IAM 出站 Gateway。
3. 仅填写当前场景需要的本地变量。不要把真实凭据、令牌或个人数据同步到未经批准的团队空间或导出文件。环境模板将凭据变量标为 secret，这本身不保证禁止同步；仍需使用批准的本地秘密管理方式。
4. `app_scope` 按配套单应用约定填写 `<API_APP_ID>/.default`。员工令牌必须面向中间层 API，并满足已配置的客户端和 scope 校验。
5. 员工 OAuth 需要先配置批准的客户端与真实回调。本集合不注册应用，不改变 Entra 权限，也不从 Quick 中提取令牌。取得面向中间层 API 的员工 access token 后，填写本地环境变量 `user_access_token`；文件夹保持 Bearer Token，子请求继承文件夹授权。具体机密 Web 客户端加 PKCE 的字段表见系列第一篇和第三篇；没有批准回调和凭据使用前，不执行该工程复核。

## 请求顺序

选择与目标相符的文件夹，分别执行 Initialize、Initialized、List tools 和 Call。

- 初始协议版本为已有基础样例使用的 `2025-03-26`。收到初始化响应后，将 `protocol_version` 改为服务实际协商的版本。
- 如果响应包含 `Mcp-Session-Id`，将其填入 `mcp_session_id`，并在后续请求中启用同名 header。未返回该头时保持禁用。切换端点或员工后，重新初始化，不复用别人的 session。
- 从实际 `tools/list` 响应复制完整工具名，分别填写 `tool_name`、`maintenance_tool_name` 或 `obo_tool_name`。若列表分页，继续取得所需工具。
- 库存工具使用 `DEMO-PART-001`，基础预期为 `DEMO-CN` 和 `12`；维修工具使用 `P-DEMO-001`，基础预期为 `DEMO-GUIDE-001`。这些都是合成数据。
- 对未知配件的业务错误不能当作身份权限拒绝测试。
- JSON 和 SSE 响应均需查看实际内容。HTTP 200、JSON-RPC 正确和工具业务成功是分别检查的条件。
- Initialize 和 Initialized 通知不是业务查询。通知可能没有内容；检查其被接受，再继续列出工具。

## 身份区别

IAM 文件夹使用 Postman AWS Signature，Service Name 为 `bedrock-agentcore`，区域为实际中国区域。临时凭据需同时提供 session token。
Gateway OAuth 出站文件夹仍使用 IAM 入站；不要在该请求上叠加 Entra Bearer token。
应用 JWT 文件夹使用 token endpoint 返回的应用访问令牌。用户 JWT 与 OBO 文件夹使用面向中间层 API 的员工访问令牌。

证书客户端认证需要应用生成签名断言；Postman 的 TLS client certificate 设置不等于 Entra private_key_jwt。OBO 在被测 Runtime 中执行，集合不会代替后端持有或生成证书凭据。

## 留存结果

按每条用例保存环境代号、身份代号、输入、HTTP 状态、协议或工具错误、业务返回、来源系统对照、时间和请求编号。
截图隐藏令牌、密钥、完整环境 ID 和个人资料。使用通过、失败、未执行三个状态，说明未执行的前提。
Postman 接口调用不替代任务平台验收，也不证明真实工单或库存权限已经实施。
