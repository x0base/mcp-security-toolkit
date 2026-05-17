"""End-to-end smoke test: spawn the MCP server over stdio and call both tools."""
import asyncio
import json

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    import sys
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_security_toolkit.server"],
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        tools = await session.list_tools()
        print("=== Registered tools ===")
        for t in tools.tools:
            print(f"  - {t.name}")

        print("\n=== call jwt_inspect (alg:none) ===")
        r = await session.call_tool(
            "jwt_inspect",
            {
                "token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
                "check_weak_secrets": False,
            },
        )
        print(json.dumps(json.loads(r.content[0].text), indent=2)[:600])

        print("\n=== call mcp_server_audit (own server.py) ===")
        r = await session.call_tool(
            "mcp_server_audit",
            {"path": "src/mcp_security_toolkit/server.py"},
        )
        print(json.dumps(json.loads(r.content[0].text), indent=2)[:600])


if __name__ == "__main__":
    asyncio.run(main())
