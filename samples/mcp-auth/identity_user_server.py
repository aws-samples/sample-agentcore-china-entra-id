"""MCP entry for the native Identity user authorization web sample."""
import anyio
from mcp.server.mcpserver import Context, MCPServer
from starlette.responses import JSONResponse

from identity_user_core import BEGIN_TOOL, CHECK_TOOL, run

server = MCPServer("entra_china_identity_user", version="0.1.0",
                   instructions="Native Identity employee authorization. Used by the sample web backend.")


def header(ctx):
    request = ctx.request_context.request
    return request.headers.get("Authorization", "") if request is not None else ""


@server.tool(name=BEGIN_TOOL, annotations={"readOnlyHint": False, "destructiveHint": False})
async def begin_authorization(ctx: Context) -> dict:
    """Start a new user authorization. The trusted web backend handles the returned URL."""
    return await anyio.to_thread.run_sync(lambda: run(header(ctx), begin=True))


@server.tool(name=CHECK_TOOL, annotations={"readOnlyHint": True, "destructiveHint": False})
async def check_my_graph_identity(ctx: Context) -> dict:
    """Retrieve this employee's token through native Identity and check China Graph /me."""
    return await anyio.to_thread.run_sync(lambda: run(header(ctx)))


@server.custom_route("/ping", methods=["GET"])
async def ping(request):
    return JSONResponse({"status": "Healthy"})


if __name__ == "__main__":
    # AgentCore's MCP container contract requires this bind address. Runtime
    # authentication and identity_user_core token validation remain required.
    server.run(transport="streamable-http", host="0.0.0.0", port=8000,  # nosec B104
               stateless_http=True, json_response=True)
