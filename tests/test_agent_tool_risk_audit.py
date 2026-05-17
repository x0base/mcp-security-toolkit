from mcp_security_toolkit.tools.agent_tool_risk_audit import agent_tool_risk_audit


def _findings(report, category):
    return [f for f in report["findings"] if f["category"] == category]


def test_format_openai():
    r = agent_tool_risk_audit({
        "type": "function",
        "function": {
            "name": "lookup_user",
            "description": "Look up a user by their unique identifier and return profile data.",
            "parameters": {
                "type": "object",
                "properties": {"id": {"type": "string", "pattern": "^[a-z0-9]{8}$"}},
                "required": ["id"],
            },
        },
    })
    assert r["detected_format"] == "openai"
    assert r["tool_name"] == "lookup_user"
    assert not any(f["severity"] == "high" for f in r["findings"])


def test_format_anthropic():
    r = agent_tool_risk_audit({
        "name": "t", "description": "x" * 80,
        "input_schema": {"type": "object", "properties": {}},
    })
    assert r["detected_format"] == "anthropic"


def test_format_mcp():
    r = agent_tool_risk_audit({
        "name": "t", "description": "x" * 80,
        "inputSchema": {"type": "object", "properties": {}},
    })
    assert r["detected_format"] == "mcp"


def test_bare_path_param_is_high():
    r = agent_tool_risk_audit({
        "name": "read_file",
        "description": "Read a file from disk and return contents as text.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    })
    overbroad = _findings(r, "over-broad-param")
    assert any(f["severity"] == "high" and "path" in f["message"] for f in overbroad)


def test_bare_command_param_is_high():
    r = agent_tool_risk_audit({
        "name": "shell_run",
        "description": "Execute a shell command on the host and return stdout.",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    })
    overbroad = _findings(r, "over-broad-param")
    assert any(f["severity"] == "high" for f in overbroad)


def test_bare_url_param_is_high():
    r = agent_tool_risk_audit({
        "name": "fetch_url",
        "description": "Fetch the body of a remote URL via HTTP GET.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    })
    assert any(f["severity"] == "high" and "url" in f["message"] for f in _findings(r, "over-broad-param"))


def test_pattern_constrained_path_is_not_flagged():
    r = agent_tool_risk_audit({
        "name": "read_log",
        "description": "Read a log file from the allowed logs directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "pattern": "^/var/log/[a-z0-9_-]+\\.log$"}},
            "required": ["path"],
        },
    })
    assert not _findings(r, "over-broad-param")


def test_exfil_shape_detected():
    r = agent_tool_risk_audit({
        "name": "post_data",
        "description": "Send arbitrary data to a remote endpoint via HTTP POST.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "data": {"type": "string"},
            },
            "required": ["url", "data"],
        },
    })
    assert _findings(r, "exfil-shape")


def test_dangerous_default_path():
    r = agent_tool_risk_audit({
        "name": "list_dir",
        "description": "List a directory's contents. Defaults to filesystem root.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "pattern": "^/.*", "default": "/"}},
        },
    })
    assert _findings(r, "dangerous-default")


def test_disabled_safety_default():
    r = agent_tool_risk_audit({
        "name": "http_get",
        "description": "Issue an HTTP GET request to a fixed allow-listed host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "pattern": "^/[a-z]+$"},
                "verify_ssl": {"type": "boolean", "default": False},
            },
        },
    })
    assert _findings(r, "dangerous-default")


def test_missing_description_high():
    r = agent_tool_risk_audit({"name": "x", "inputSchema": {"type": "object", "properties": {}}})
    desc = _findings(r, "ambiguous-description")
    assert any(f["severity"] == "high" for f in desc)


def test_short_description_medium():
    r = agent_tool_risk_audit({
        "name": "x", "description": "Do thing.",
        "inputSchema": {"type": "object", "properties": {}},
    })
    desc = _findings(r, "ambiguous-description")
    assert any(f["severity"] == "medium" for f in desc)


def test_risky_name_with_brief_desc_flagged():
    r = agent_tool_risk_audit({
        "name": "exec_query",
        "description": "Runs a query.",
        "inputSchema": {"type": "object", "properties": {}},
    })
    assert _findings(r, "risky-name-vague-desc")


def test_risky_name_with_thorough_desc_not_flagged():
    r = agent_tool_risk_audit({
        "name": "exec_query",
        "description": "Execute a parameterized SQL query against the read-only analytics replica. Bound parameters only. Returns at most 1000 rows.",
        "inputSchema": {"type": "object", "properties": {}},
    })
    assert not _findings(r, "risky-name-vague-desc")


def test_open_object_param():
    r = agent_tool_risk_audit({
        "name": "store_metadata",
        "description": "Persist a metadata blob alongside an entity record.",
        "inputSchema": {
            "type": "object",
            "properties": {"meta": {"type": "object"}},
        },
    })
    assert _findings(r, "over-broad-param")


def test_unbounded_array_flagged():
    r = agent_tool_risk_audit({
        "name": "batch_lookup",
        "description": "Look up multiple records in a single call given a list of IDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string", "pattern": "^[a-z0-9]{8}$"}},
            },
        },
    })
    assert _findings(r, "missing-constraint")


def test_summary_counts():
    r = agent_tool_risk_audit({
        "name": "shell",
        "description": "run",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    })
    assert r["summary"].get("high", 0) >= 1


def test_non_dict_input():
    r = agent_tool_risk_audit("not a dict")  # type: ignore[arg-type]
    assert "error" in r
