"""Shared synthetic tools. Authentication is enforced by the Runtime front door.

These tools contain no employee-specific data and make no business ACL claim.
Never use the illustrative maintenance text for actual vehicle repair.
"""
from mcp.server.mcpserver import MCPServer
from starlette.responses import JSONResponse

server = MCPServer(
    "china-maintenance-auth-sample",
    version="0.1.0",
    instructions="Read-only synthetic maintenance and parts examples for authentication integration.",
)


@server.tool()
def get_maintenance_guide(fault_code: str) -> dict:
    """Get a synthetic maintenance guide for P-DEMO-001; no actual repair advice."""
    if fault_code != "P-DEMO-001":
        raise ValueError("UNKNOWN_SYNTHETIC_FAULT_CODE")
    return {
        "guide_id": "DEMO-GUIDE-001",
        "fault_code": fault_code,
        "title": "合成维修演示",
        "steps": ["记录演示故障码", "查阅合成知识条目", "按企业实际流程处理"],
        "synthetic": True,
    }


@server.tool()
def get_parts_stock(part_number: str) -> dict:
    """Read shared synthetic parts stock. Use DEMO-PART-001."""
    if part_number != "DEMO-PART-001":
        raise ValueError("UNKNOWN_SYNTHETIC_PART")
    return {"part_number": part_number, "warehouse": "DEMO-CN", "quantity": 12, "synthetic": True}


@server.tool()
def describe_access_boundary() -> dict:
    """Explain the sample's shared-data boundary without returning credentials."""
    return {
        "data_classification": "shared synthetic demonstration data",
        "authentication": "enforced by configured AgentCore Runtime authorizer",
        "employee_resource_acl_implemented": False,
        "credentials_in_tool_arguments": False,
    }


@server.custom_route("/ping", methods=["GET"])
async def ping(request):
    return JSONResponse({"status": "Healthy"})


if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        # AgentCore's MCP container contract requires this bind address;
        # authentication is enforced by the configured Runtime authorizer.
        host="0.0.0.0",  # nosec B104
        port=8000,
        stateless_http=True,
        json_response=True,
    )
