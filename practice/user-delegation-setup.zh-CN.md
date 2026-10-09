# 中国区域用户授权页面与 Runtime OBO 部署

本说明配套第三篇。路线一在企业 HTTPS 页面中集成 AgentCore Identity `USER_FEDERATION`，承接中国区域没有 Consent portal 时的用户交互；路线二在 Runtime 中使用 MSAL 与应用证书执行 Entra OBO。两个实现均已包含在材料包中，按需部署其中一条即可。

先阅读[全球托管门户与中国区域页面图解](portal-walkthrough.zh-CN.md)，了解两种方案的分工以及员工登录、授权、回调和调用成功的实际画面。要运行中国区页面，完成下文第1、2节即可；第3节 OBO 是独立选项。

## 1 准备部署环境

部署管理员使用 Linux 或 macOS、Python 3.12，以及已获准管理本实验资源的中国区域 AWS profile。准备本区域的私有 S3 代码桶，开启全部阻止公有访问选项，并设置 `Project` 标签。

用户 OAuth 路线使用 Runtime、Identity、API Gateway、Lambda、DynamoDB、Secrets Manager、S3、IAM 和 CloudWatch Logs。OBO 路线使用 Runtime、Secrets Manager、S3、IAM 和 CloudWatch Logs。员工浏览器不需要部署权限。

解压配套 ZIP，进入 `sample-agentcore-china-entra-id-main/samples/mcp-auth`。后续命令均在此目录执行：

```bash
export AWS_PROFILE=agentcore-cn
export AWS_DEFAULT_REGION=cn-north-1
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt uv
mkdir -p .state
if [ ! -e .state/config.json ]; then
  cp config.example.json .state/config.json
fi
```

`agentcore-cn` 替换为自己的中国区域 profile。填写 `.state/config.json`：

| 字段 | 本环境配置 |
|---|---|
| `account_id`、`region` | 部署账号与中国区域 |
| `tenant_id` | 世纪互联 Entra 租户 ID |
| `api_app_id`、`client_app_id` | 本篇专用应用的同一个 client ID |
| `authority_host` | `https://login.partner.microsoftonline.cn` |
| `scope` | `agent.invoke` |
| `bucket` | 私有代码桶名称 |
| `bucket_project_tag` | 代码桶的 `Project` 标签值 |
| `project_tag` | 本实践资源的项目标签 |
| `runtime_prefix`、`gateway_prefix` | 本次独立资源前缀，使用模板格式 |

现成示例采用单应用配置；其页面登录、provider 凭据和 OBO 证书都属于这个应用。前两篇采用分离客户端时，另用本篇专用配置，不覆盖前两篇的部署状态。

在 Entra 按第三篇完成 `agent.invoke`、v2 access token、工具 API 委托权限和中国云 Graph Delegated `User.Read`。按组织规则完成同意。

构建 Linux ARM64 后端依赖；本步骤由部署管理员执行一次，两条路线共用：

```bash
.venv/bin/uv pip install \
  --python-version 3.12 \
  --python-platform aarch64-manylinux2014 \
  --only-binary :all: \
  --target build/cloud-obo-package \
  -r requirements-cloud-obo.lock
```

## 2 部署企业授权页面与 Identity

### 2.1 创建 provider

在 Entra 本篇应用创建 client secret，使用下面的交互命令录入 Value；输入不回显：

```bash
.venv/bin/python identity_user_setup.py stage-secret
.venv/bin/python identity_user_setup.py configure-provider
```

程序创建 `CustomOauth2` provider，并把名称、ARN、托管 secret 引用和服务实际返回的 callback 保存到 `.state/identity-user-provider.json`。已创建时核对同一份状态再继续，不在控制台重复创建同名 provider。

### 2.2 部署页面和 Runtime

```bash
.venv/bin/python identity_user_deploy.py deploy
.venv/bin/python identity_user_deploy.py status
```

程序创建 HTTPS API、页面 Lambda、会话表、JWT Runtime、workload identity 和专用角色，并登记应用 return URL。状态输出写入 `results/identity-user-deployment.json`：

| 输出字段 | 用途 |
|---|---|
| `deployment_ready` | 为 `true` 时页面与 Runtime 已就绪 |
| `portal_url` | 员工打开的 HTTPS 首页 |
| `entra_web_redirects` | 需要登记到 Entra 的两条 Web callback |
| `workload_application_return_url` | 已登记到 workload identity 的应用 return URL |

在 Entra **Authentication → Web** 登记 `entra_web_redirects` 中的两条完整地址。页面登录 callback 以 `/login/callback` 结尾，另一条为 Identity 返回的 provider callback。workload 的 return URL 以 `/identity/callback` 结尾，不将它重复登记为 Entra callback。

程序保存的 callback 登记状态不会代替实际控制台操作；以 Entra 中保存的地址为准。无需修改 AWS 托管 Consent portal 设置。

### 2.3 员工使用

打开 `portal_url`，依次选择 **企业登录 → 开始授权 → 继续至 Entra**。完成本次授权返回后，页面后端核对当前会话、`customState` 与授权 session，调用 `CompleteResourceTokenAuth`。

选择 **运行验证**，查看 Graph HTTP 200、同一用户以及 Identity 已取得令牌的结果。此时 Runtime 调用了真实的中国云 Graph。员工全程只使用浏览器。

### 2.4 集成已有前端

保留以下关系，再将页面交互接入企业现有会话：

1. Runtime 使用经过验证的员工 JWT 调用 `GetWorkloadAccessTokenForJWT`。
2. 使用返回的 workload token 调用 `GetResourceOauth2Token`，流程为 `USER_FEDERATION`，下游 scope 为中国云 Graph `User.Read`。
3. 需要用户授权时，把返回的 authorization URL 和本次事务与当前会话关联。
4. HTTPS return handler 核对当前有效用户会话、`customState` 和授权 session，再调用 `CompleteResourceTokenAuth`。
5. Runtime 重新取该用户的下游令牌并访问 Graph。

示例代码分别位于 `identity_user_core.py`、`identity_user_server.py`、`identity_user_web.py` 和 `identity_user_static/`。用户 OAuth 的默认操作入口是浏览器，本集合不提供绕过页面会话绑定的 Postman 授权替代请求。

## 3 部署 Runtime MSAL OBO

本路线可以独立于第2节部署，不需要 Identity provider 或授权页面。

### 3.1 准备并注册公钥

```bash
.venv/bin/python cloud_obo_deploy.py prepare-certificate
```

把生成的 `dist/cloud-obo-runtime-public.cer` 上传到 Entra 本篇应用的 **Certificates & secrets → Certificates**。核对公钥指纹和有效期；示例证书有效期为30天。

### 3.2 部署 Runtime

```bash
.venv/bin/python cloud_obo_deploy.py deploy
.venv/bin/python cloud_obo_deploy.py status
```

程序创建专用证书 secret、执行角色及 JWT Runtime。它配置 Authorization 头传递，并把 secret ARN 提供给后端。确认 `runtime_status` 为 `READY`，`deployment_configuration_ready` 为 `true`。

Runtime 调用地址保存在 `.state/cloud-obo-deployment.json` 的 `runtime.url`。原样复制完整值，不自行拼接 ARN 或修改 query string。

### 3.3 配置员工客户端

在 Entra 本篇应用的 **Authentication → Mobile and desktop applications** 登记 `http://localhost:8400`。保留用户 OAuth 已有的 Web callbacks。

员工从材料包取得 `samples/mcp-auth` 中的客户端文件及 `requirements-login.txt`，自行创建 `.state/config.json`，按本说明的非秘密字段填写自己的部署信息；不复制管理员的完整 `.state` 目录。另创建 `.state/cloud-obo-deployment.json`，只填写：

```json
{
  "runtime": {
    "url": "REPLACE_WITH_THE_COMPLETE_RUNTIME_URL"
  }
}
```

管理员只提供应用、租户、区域和 Runtime endpoint 等非秘密值。员工不需要 secret、证书私钥或 AWS 访问密钥。

Windows 员工在 `samples/mcp-auth` 运行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-login.txt
.\.venv\Scripts\python.exe cloud_obo_client.py
```

Linux 或 macOS 员工运行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-login.txt
.venv/bin/python cloud_obo_client.py
```

按终端提示，在同一台设备浏览器打开 `http://localhost:8400/start` 并完成企业登录。客户端自动初始化、列出工具并调用 `entra_check_my_graph_identity`，参数为 `{}`。结果写入 `results/cloud-obo.json`，展示 Graph 调用和同一用户匹配结果。

### 3.4 使用已有客户端或 Postman

已有客户端应取得面向本 API 的用户 access token，并将其作为 Bearer token 调用上述 Runtime endpoint。应用证书留在 Runtime 后端。

Postman 集合中的 **05 Runtime OBO Graph** 提供四个手动请求，`obo_runtime_url` 填完整 endpoint，`employee_api_access_token` 填当前获准客户端取得的 API 用户令牌。令牌字段为本地秘密值，不随材料导出。工具名称从 `tools/list` 复制到 `obo_tool_name`；参数是空对象，不使用原 OpenAPI 路线的 `$select` 参数。

如果当前客户端没有已获准的令牌获取方式，使用第3.3节的现成本机客户端即可。不要把本机客户端的 localhost 回调直接当作另一个产品的 OAuth 回调。

## 4 维护配置

企业应用负责自己的登录会话、回调处理和业务 API 权限。Identity 路线的 client secret 与 OBO 路线的证书分别按对应资源维护。变更应用、回调或资源 prefix 时，同时核对 workload return URL、JWT authorizer 和角色资源引用。

本示例的下游权限仅为 Graph `User.Read`。实际业务在接入新的 API 后，按其要求配置委托权限与数据访问规则。
