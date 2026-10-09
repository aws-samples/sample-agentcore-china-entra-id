"""MCP tool that uses the verified inbound employee token to perform cloud OBO."""
import anyio
from mcp.server.mcpserver import Context, MCPServer
from starlette.responses import JSONResponse

from cloud_obo_core import TOOL_NAME, run_identity_check

server = MCPServer(
    "entra_china_obo_mcp",
    version="0.1.0",
    instructions="Check the current employee's Graph identity through certificate OBO. No token arguments.",
)


@server.tool(
    name=TOOL_NAME,
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def check_my_graph_identity(ctx: Context) -> dict:
    """Use this request's authenticated employee to check China Graph /me via OBO.

    Returns the Graph HTTP status, request ID and whether the same user was
    returned. No user identifiers, credentials or tokens are returned.
    """
    request = ctx.request_context.request
    authorization = request.headers.get("Authorization", "") if request is not None else ""
    return await anyio.to_thread.run_sync(run_identity_check, authorization)


@server.custom_route("/ping", methods=["GET"])
async def ping(request):
    return JSONResponse({"status": "Healthy"})


if __name__ == "__main__":
    server.run(
        # Required inside the AgentCore container; the Runtime authorizer
        # and the tool's independent token validation protect invocation.
        transport="streamable-http", host="0.0.0.0", port=8000,  # nosec B104
        stateless_http=True, json_response=True,
    )
