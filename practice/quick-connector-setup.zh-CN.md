# 使用 Amazon Quick 连接中国区域 AgentCore 工具

本文配合第一篇第8节，使用 Quick 云端 MCP 连接器调用中国北京区域的库存与维修工具。Quick 位于 `us-east-1`，Gateway、IAM Runtime 和 OAuth 参数兼容入口位于 `cn-north-1`。工具请求直接进入 Gateway；OAuth 请求通过兼容入口到世纪互联 Entra。

## 适用条件

这份配套实现专门用于**复用同一个现有 Entra 应用作为客户端和资源 API**的场景，配置中 `client_app_id=api_app_id`，scope 使用 `<API_APP_ID>/agent.invoke`。它和正文第3、4节新建两个应用的配置是两条不同路径，不能混填。

需要：

- 可创建 MCP 连接器的 Amazon Quick Enterprise 环境。
- 已就绪的 JWT Gateway、IAM MCP Runtime 和库存工具。
- 已有 Entra 应用，启用 `agent.invoke` 委托权限，设置 v2 访问令牌，并完成相应同意。
- 该应用的 Web 客户端凭据，以及精确登记的 Quick 回调。
- 允许 Quick 访问两个公网 HTTPS 入口的网络条件。

Quick 云端会处理连接凭据、工具输入和返回数据。随包示例只处理合成库存与维修资料；实际业务接入时按组织的数据流向要求部署。

## 1 准备现有应用和 Gateway

打开 Quick 的 MCP 创建页面，复制其显示的 **Redirect URL**。本例 `us-east-1` 的值为：

```text
https://us-east-1.quicksight.aws.amazon.com/sn/oauthcallback
```

在世纪互联 Entra 中打开现有应用的 **Authentication → Web**，登记同一个回调。客户端密钥由 Quick 服务端保管，不放入员工设备、Git 仓库或截图。

Gateway 的 `aud` 与 `azp` 在本单应用例子中均对应现有应用 ID，`scp` 要求 `agent.invoke`，`tid` 限定本租户。后端 IAM target 的服务角色只获得对应 Runtime 调用权限。

已有随包示例部署时，复用 `samples/mcp-auth/.state/config.json` 和 `.state/deployment.json`。尚未部署此 MCP 示例时，先按[扩展说明的环境配置、共用 Runtime 与员工登录入口](../extensions/scripted-deployment.zh-CN.md)准备资源。仅使用正文 Lambda 双应用路径的读者，不直接运行下面这个单应用部署程序。

## 2 部署 OAuth 参数兼容入口

从 `samples/mcp-auth` 目录使用已有虚拟环境和中国区 AWS 部署身份。先查看将创建的资源及绑定配置：

```bash
.venv/bin/python quick_oauth_compat_deploy.py --plan
```

核对租户、应用、Gateway 完整 `/mcp` 地址和 Quick 回调，然后部署：

```bash
.venv/bin/python quick_oauth_compat_deploy.py
```

程序使用当前 AWS 凭据链，新增 Regional API Gateway REST API、Lambda、专用日志组及仅写该日志组的执行角色。它不会修改现有 Entra 应用、Gateway 或 Runtime。部署结果保存到 `.state/quick-oauth-compat-deployment.json`。

记录输出中的：

| 输出字段 | Quick 中的用途 |
|---|---|
| `adapter_config.resource_uri` | MCP server endpoint |
| `authorization_url` | Authorization URL |
| `token_url` | Token URL |
| `adapter_config.redirect_uri` | 与 Quick 的 Redirect URL 核对 |

兼容组件固定允许所配置的客户端、MCP 资源和回调，把资源与 scope 参数转换成该应用的 Entra v2 请求，并保留 state、S256 PKCE 和原 Quick 回调。它不签发 JWT，也不放宽 Gateway 校验。授权码、密钥、PKCE verifier 和令牌仅在交换请求的内存中处理，不写入应用日志或配置。

此版本把中国云 authority 与 `us-east-1` Quick 回调限定为精确值。换用其他 Quick 区域时，必须同步调整代码中的回调限制和 Entra 登记值，不能只改表单。

## 3 配置 Quick

进入 **Connectors → Create for your team → Model Context Protocol**，或从桌面端 **Customize → Connectors → Create → Cloud connector** 打开云端页面。

| 页面字段 | 填写内容 |
|---|---|
| Name | `AgentCore China Entra Practice` |
| Description | `Enterprise sign-in for demo parts stock and maintenance tools through AWS China AgentCore.` |
| MCP server endpoint | 自己 JWT Gateway 的完整 `/mcp` 地址 |
| Connection type | 本例为 Public network |
| Auth server connection type | 本例为 Public network |
| Authentication | User authentication / Custom user based OAuth |
| Client ID | 现有 Entra 应用 ID |
| Public OAuth client | 不勾选 |
| Client secret | 现有应用的有效 Web 客户端密钥 |
| Authorization URL / Token URL | 第2步两个部署输出 |
| Redirect URL | 核对 Quick 页面显示值与 Entra、适配器一致 |

本表单没有本例的手工 Scope 输入框。完整 API scope 由兼容组件根据绑定配置构造。

选择 **Create and continue**，完成世纪互联 Entra 登录。回到 Quick 后，启用库存工具所需的读取操作；发布时先关闭组织范围分享并保留为空的额外用户组，创建供本人使用的连接器。

## 4 在助手中使用库存工具

桌面端进入 **Customize → Connectors → Refresh connections**，启用云端连接器，新建对话并输入：

```text
请使用 AgentCore China Entra Practice 的库存工具查询 DEMO-PART-001，
展示实际输入、仓库和返回数量，只使用该连接器的合成数据。
```

展开工具详情，核对输入 `part_number=DEMO-PART-001`，返回 `warehouse=DEMO-CN`、`quantity=12`、`synthetic=true`。仓库是输出字段，不是此工具的输入参数。

Gateway 增加或修改工具后，在 Quick 云端连接器详情执行 **Sync** 并完成相应授权，再刷新桌面端连接。工具的完整名称采用 Gateway 实际发现值。

## 其他客户端与原生 Quick 集成

其他企业助手需要支持远程 MCP HTTP、所用会话方式、用户授权码流程和 S256 PKCE，并让资源、scope、回调与 Gateway 规则一致。为各客户端登记其应用和回调，按客户端 ID 限定相应入口；不要把这一 Quick 配置当作所有助手通用的表单。

[官方 MCP 文档](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html)另提供独立客户端与资源应用、Entra v1 OAuth 端点及 v2 访问令牌的配置参考。本文没有提供该原生双应用路径在本中国云环境中的运行证据；实际运行路径是上面的单应用参数兼容方案。兼容组件中的 refresh 分支尚无真实续期生命周期证据，不应据此宣称已验证无人值守长期续期。
