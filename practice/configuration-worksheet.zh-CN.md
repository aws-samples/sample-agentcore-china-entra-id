# 实践配置工作表

复制本表记录自己的非秘密配置。不要填写密码、client secret、私钥或访问令牌。

| 配置 | 本环境值 |
|---|---|
| AWS 区域 | cn-north-1 |
| Entra TENANT_ID | 待填写 |
| 资源 API_APP_ID | 待填写 |
| 资源 Application ID URI | 待填写 |
| 员工 USER_CLIENT_ID | 待填写 |
| 员工客户端实际 callback | 待填写 |
| 后台 MACHINE_CLIENT_ID | 待填写 |
| PartsFunctionArn 或现有 MCP endpoint | 待填写 |
| 员工 Gateway URL 和 ARN | 待填写 |
| IAM Gateway URL 和 ARN | 待填写 |
| 应用 Gateway URL 和 ARN | 待填写 |
| OAuth relay Gateway URL 和 ARN | 待填写 |
| M2M provider ARN | 待填写 |
| 第三篇专用 API_APP_ID 与 client_app_id | 现成示例填写同一个应用 ID |
| 企业应用 HTTPS 首页 portal_url | 部署输出的完整 URL |
| 页面 PORTAL_BASE_URL | 包含 stage 路径，例如 /test |
| 页面登录 callback | PORTAL_BASE_URL/login/callback，登记 Entra Web redirects |
| Identity 用户 OAuth provider ARN | 待填写 |
| Graph provider 返回的完整 callbackUrl | 待填写 |
| workload identity 名称与 ARN | 待填写 |
| 应用 return URL | PORTAL_BASE_URL/identity/callback，登记 workload 允许列表 |
| Identity 路线 Runtime URL | 部署输出的完整 URL |
| OBO 中间层 client ID | 应与入口用户 token 的 API_APP_ID 对应 |
| OBO Runtime URL | 部署输出 runtime.url 的完整值 |
| OBO certificate secret ARN | 待填写，只记录引用 |
| OBO 员工客户端 callback | http://localhost:8400，登记 Mobile and desktop |

## 第三篇的实现方式

中国区域不支持 Consent portal。第三篇使用企业 HTTPS 页面承接用户交互，Identity USER_FEDERATION 管理下游授权；OBO 由 Runtime 中的 MSAL 完成。配置方法见[用户委托部署说明](user-delegation-setup.zh-CN.md)。
