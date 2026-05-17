from mcp.server.fastmcp import FastMCP

from mcp_security_toolkit.tools import (
    agent_tool_risk_audit,
    default_creds_lookup,
    graphql_introspect,
    http_diff,
    interactsh,
    jwt_inspect,
    mcp_server_audit,
    owasp_llm_classify,
    phpggc_generate,
    prompt_injection_audit,
    sensitive_files_list,
    wordlist_gen,
)

mcp = FastMCP("mcp-security-toolkit")

# v0.1 — LLM/agent security + appsec primitives
mcp.tool()(mcp_server_audit.mcp_server_audit)
mcp.tool()(agent_tool_risk_audit.agent_tool_risk_audit)
mcp.tool()(prompt_injection_audit.prompt_injection_audit)
mcp.tool()(owasp_llm_classify.owasp_llm_classify)
mcp.tool()(jwt_inspect.jwt_inspect)
mcp.tool()(http_diff.http_diff)

# v0.2 — pentest pack
mcp.tool()(default_creds_lookup.default_creds_lookup)
mcp.tool()(sensitive_files_list.sensitive_files_list)
mcp.tool()(wordlist_gen.wordlist_gen)
mcp.tool()(graphql_introspect.graphql_introspect)
mcp.tool()(phpggc_generate.phpggc_generate)
mcp.tool()(interactsh.interactsh_register)
mcp.tool()(interactsh.interactsh_poll)
mcp.tool()(interactsh.interactsh_stop)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
