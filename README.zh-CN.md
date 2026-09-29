# AgentCore 中国区域与世纪互联 Entra ID 认证示例

本仓库提供文章配套的部署代码、客户端、Web 授权页面、配置模板和依赖清单。MCP 工具使用合成维修指引和备件库存；用户委托示例通过中国云 Microsoft Graph `User.Read` 核对当前用户身份。

[下载完整代码 ZIP](https://github.com/weichaoabc/agentcore-china-entra-id-samples/archive/refs/heads/main.zip)，或克隆仓库后进入示例目录：

```bash
git clone https://github.com/weichaoabc/agentcore-china-entra-id-samples.git
cd agentcore-china-entra-id-samples/samples/mcp-auth
```

## 环境与配置

云端部署命令使用 Linux 或 macOS、Python 3.12 或更新的兼容版本。准备自己的 AWS 中国区域账号、世纪互联 Entra 租户和应用注册，以及开启全部 S3 public access block、带 `Project` 标签的私有代码桶。

部署身份需要管理所选场景的 AgentCore、IAM、S3 资源。Web 场景还使用 API Gateway、Lambda、DynamoDB；OBO 使用 Secrets Manager。部署角色与日常业务调用角色分别配置。Gateway OAuth 验证脚本还会准备并承担受限调用角色。

以下 `agentcore-cn` 是已有的中国区域部署 profile：

```bash
export AWS_PROFILE=agentcore-cn
export AWS_DEFAULT_REGION=cn-north-1
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt uv
mkdir -p .state
cp config.example.json .state/config.json
```

编辑 `.state/config.json`，填入自己的 AWS 账号、区域、代码桶、桶标签、租户、应用 ID 和资源前缀。已有配置时不要再次覆盖。

配套示例复用一个现有 Entra 应用作为客户端和资源 API，`client_app_id=api_app_id`。在 Entra 中：

1. 在 **Expose an API** 设置 Application ID URI，例如 `api://<API_APP_ID>`，启用 delegated scope `agent.invoke`。
2. 在应用 Manifest 设置 `api.requestedAccessTokenVersion=2`。
3. 为客户端完成调用此 API 所需的权限与同意。
4. 员工本机登录时，在 **Mobile and desktop applications** 登记 `http://localhost:8400`。

配置文件的 `scope` 只填 `agent.invoke`。同一应用示例在令牌请求中使用 `<API_APP_ID>/agent.invoke`，应用令牌使用 `<API_APP_ID>/.default`，由脚本生成。Quick 适配器也依赖这一约定。分别注册 API 和客户端时，需要一起调整 scope 构造、权限、authorizer 和适配器。

`.state/` 保存本环境配置和部署状态，`results/` 保存本地运行结果。GitHub 不提供已部署环境的地址、凭据或客户运行报告。

## 部署共用 MCP Runtime

仅使用 IAM 时，可以先填写 AWS 字段，暂不配置 Entra。

```bash
.venv/bin/uv pip install \
  --python-version 3.12 \
  --python-platform aarch64-manylinux2014 \
  --only-binary :all: \
  --target build/package \
  -r requirements-runtime.lock
.venv/bin/python lab.py package
.venv/bin/python lab.py deploy --mode iam
.venv/bin/python lab.py status
```

等待 Runtime `READY`。后续每次运行 `lab.py gateways --mode ...`，先创建 Gateway，再等待其 `READY`，重复同一命令添加 target，直到 `target_status` 为 `READY`。资源地址写入 `.state/deployment.json`。

三个工具分别为：

| 工具 | 输入 | 结果 |
|---|---|---|
| `get_maintenance_guide` | `fault_code=P-DEMO-001` | `guide_id=DEMO-GUIDE-001` |
| `get_parts_stock` | `part_number=DEMO-PART-001` | `warehouse=DEMO-CN`、`quantity=12` |
| `describe_access_boundary` | 无 | 共享合成数据说明 |

维修数据仅用于演示接口调用。Gateway 工具名包含 target 前缀，由客户端读取工具列表后使用。

## 员工登录

准备 Entra scope、本机 callback 和 IAM Runtime 后：

```bash
.venv/bin/python lab.py deploy --mode jwt
.venv/bin/python lab.py status
.venv/bin/python lab.py gateways --mode jwt
.venv/bin/python lab.py status
```

等待 Gateway 就绪后重复 `gateways --mode jwt`，完成 target。员工电脑先下载代码，并由部署方提供该环境的非秘密 `.state/config.json` 和 `.state/deployment.json`。只复制所需配置，不复制部署凭据。

Linux 或 macOS 员工电脑从 `samples/mcp-auth` 准备登录环境；在部署电脑上可以复用已有虚拟环境：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-login.txt
.venv/bin/python entra.py login
```

在同一台电脑打开 `http://localhost:8400/start`。登录后等待客户端完成工具请求，查看 `results/login.json` 中的两条路径和业务结果。用户 JWT Gateway 的 target 是 IAM Runtime；用户 JWT Runtime 提供直接访问路径。

Windows 员工电脑执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-login.txt
.\.venv\Scripts\python.exe entra.py login
```

先安装 Python 并加入 PATH。员工电脑不需要 AWS 凭据或应用 secret。

## IAM 程序调用

```bash
.venv/bin/python lab.py gateways --mode iam
.venv/bin/python lab.py status
```

完成两阶段 target 创建。为业务角色授予目标 Gateway 的 `bedrock-agentcore:InvokeGateway`，并在开发电脑配置已承担该角色的 profile：

```bash
AWS_PROFILE=agentcore-caller .venv/bin/python call_iam.py
```

运行在 AWS 计算环境时，使用绑定的工作负载角色。终端返回初始化、工具列表、维修指引与库存结果。

## 应用 secret 或证书

在资源 API 的 **App roles** 启用 `Mcp.Tools.Invoke`，允许类型为 **Applications**。在调用应用的 API permissions 添加对应 application permission，由管理员授予，确认 **Granted**。一应用示例为应用选择自身 API。

在配置中增加 `machine_client_app_id` 和 `machine_role`。前者与 `api_app_id` 相同，后者为 `Mcp.Tools.Invoke`。

```bash
.venv/bin/python lab.py deploy --mode app
.venv/bin/python lab.py status
.venv/bin/python lab.py gateways --mode app
.venv/bin/python lab.py status
```

完成两阶段 target 创建。将有效 secret Value 保存在受保护的文本文件，或准备已在 Entra 登记公钥的应用证书：

```bash
ENTRA_CLIENT_SECRET_FILE=/protected/path/client-secret.txt \
  .venv/bin/python machine_scenarios.py secret
```

```bash
.venv/bin/python prepare_certificate.py
```

把 `.state/client-certificate/client-public.cer` 上传到 Entra 应用 **Certificates & secrets → Certificates**，再执行：

```bash
ENTRA_PRIVATE_KEY_FILE=.state/client-certificate/client-private.pem \
ENTRA_CERTIFICATE_FILE=.state/client-certificate/client-public.pem \
  .venv/bin/python machine_scenarios.py certificate
```

证书有效期为 30 天，私钥留在受控运行环境。分别检查 `results/client-secret.json` 和 `results/client-certificate.json` 中两条 MCP 路径的结果。

## Identity M2M 与 Gateway OAuth 出站

机器入口和应用权限就绪后，用 Identity 管理客户端凭据：

```bash
ENTRA_CLIENT_SECRET_FILE=/protected/path/client-secret.txt \
  .venv/bin/python identity.py configure
.venv/bin/python machine_scenarios.py identity
```

结果写入 `results/identity-m2m.json`。应用使用 AWS 身份向 Identity 获取令牌；AWS 角色需获得访问相应 workload identity 和 provider 的权限。

让 Gateway 获取并使用 OAuth 应用令牌时，复用该 provider 和机器 JWT Runtime：

```bash
.venv/bin/python gateway_oauth.py deploy
.venv/bin/python gateway_oauth.py test
```

查看 `results/gateway-native-oauth.json`。这条路径为 IAM 调用方 → IAM Gateway → OAuth client credentials → 机器 JWT Runtime。

## Quick Cloud Connector

完成 IAM Runtime 和用户 JWT Gateway，准备可创建自定义 MCP Cloud Connector 的 Quick 账号。在复用的 Entra 应用中登记 Web callback：

```text
https://us-east-1.quicksight.aws.amazon.com/sn/oauthcallback
```

准备该 Web 客户端有效的 client secret，运行：

```bash
.venv/bin/python quick_oauth_compat_deploy.py
```

从 `results/quick-oauth-compat-deployment.json` 读取 `authorization_url`、`token_url`。在 Quick 创建 Model Context Protocol 连接器：

- MCP endpoint：自己的用户 JWT Gateway URL。
- User authentication → Custom user based OAuth。
- Client ID 和 client secret：复用的 Entra 应用。Public OAuth client 不勾选。
- Authorization URL 与 Token URL：参数兼容组件输出。
- Redirect URL：与登记的 callback 一致。
- 资源与授权服务连接类型：本例采用 Public network。

完成 Entra 授权，核对三个工具并设置权限，再在 Quick Desktop 刷新 Cloud connections。通过对话查询 `P-DEMO-001` 与 `DEMO-PART-001`，核对工具返回值。

该适配器对应同一应用复用和上述 Quick callback，校验并转换 resource/scope，保留 state 与 S256 PKCE。OAuth 交换经适配器，MCP 请求由 Quick 直接发送到 Gateway。Quick 云端在 `us-east-1`，AWS 后端在 `cn-north-1`；需要网络可达，结果经过 Quick 云端。采用其他区域时同步修改 callback 校验与 Entra 配置。

## Identity 用户 OAuth

使用自己的 Entra 应用授予中国云 Graph delegated `User.Read`，门户登录继续请求 `agent.invoke`。本流程独立部署，不依赖机器入口。

```bash
.venv/bin/python identity_user_setup.py stage-secret
.venv/bin/python identity_user_setup.py configure-provider
.venv/bin/uv pip install \
  --python-version 3.12 \
  --python-platform aarch64-manylinux2014 \
  --only-binary :all: \
  --target build/cloud-obo-package \
  -r requirements-cloud-obo.lock
.venv/bin/python identity_user_deploy.py deploy
.venv/bin/python identity_user_deploy.py status
```

将部署返回的门户登录 callback、Identity provider callback 登记到 Entra Web redirects。应用 return URL 由脚本登记在 workload 上。两个 callback 与应用 return URL 职责不同，使用服务输出的完整值。

打开门户，依次完成企业登录、开始授权、继续至 Entra、返回门户绑定、运行验证。Web 后端验证当前浏览器会话和授权事务，调用 `CompleteResourceTokenAuth`；Runtime 使用 `USER_FEDERATION` 获取下游令牌。预期 Graph HTTP 200 且用户匹配，可以下载 `identity-user-oauth.json`。

## Runtime 证书 OBO

此路径独立部署，不要求创建 Identity provider 或门户。准备上述共用依赖，在中间层 Entra 应用授予 Graph delegated `User.Read`，员工继续请求 `agent.invoke`：

```bash
.venv/bin/python cloud_obo_deploy.py prepare-certificate
.venv/bin/python cloud_obo_deploy.py deploy
.venv/bin/python cloud_obo_deploy.py status
```

上传 `.state/cloud-obo-certificate/client-public.cer` 到中间层应用的 Certificates。证书有效期 30 天，私钥由部署程序存入后端 Secrets Manager。Runtime 已配置验证后 Authorization 头的传递。

员工电脑准备登录依赖、非秘密配置和 `.state/cloud-obo-deployment.json`，运行：

```bash
.venv/bin/python cloud_obo_client.py
```

Windows 对应 `.\.venv\Scripts\python.exe cloud_obo_client.py`。在同一台电脑完成本机登录，检查 `results/cloud-obo.json`：Graph HTTP 200 且 `same_user_as_verified_token_a=true`。

该验证只调用 Graph 当前用户 ID；工单、文件或订单系统仍需检查自己的业务权限。

## 清理和本地检查

根据 `.state/` 中各场景的 deployment/provider 文件，先清理 Gateway target 与 Gateway，再处理 Runtime、专用 Web 资源和角色，最后按引用关系处理 Identity、凭据、代码对象及日志。由 Entra 应用所有者移除不再使用的 callback 和凭据，保留其他集成需要的配置。

离线单元测试从 `samples/mcp-auth` 执行，不部署云资源：

```bash
.venv/bin/python -m unittest discover -s tests
```

这些测试检查代码行为；企业应用的云端权限、实际登录、长期令牌续期和凭据轮换仍需在自己的环境验收。
