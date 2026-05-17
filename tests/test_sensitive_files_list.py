from mcp_security_toolkit.tools.sensitive_files_list import sensitive_files_list


def test_default_returns_common():
    r = sensitive_files_list()
    paths = {p["path"] for p in r["paths"]}
    assert "/.env" in paths
    assert "/.git/config" in paths


def test_wordpress_stack():
    r = sensitive_files_list("wordpress")
    paths = {p["path"] for p in r["paths"]}
    assert "/wp-admin/" in paths
    assert "/xmlrpc.php" in paths
    assert "/.env" in paths  # common is auto-included


def test_multiple_stacks():
    r = sensitive_files_list("java,k8s")
    paths = {p["path"] for p in r["paths"]}
    assert "/actuator/heapdump" in paths
    assert "/metrics" in paths


def test_no_common_when_disabled():
    r = sensitive_files_list("java", include_common=False)
    paths = {p["path"] for p in r["paths"]}
    assert "/.env" not in paths
    assert "/actuator" in paths


def test_no_duplicates():
    r = sensitive_files_list("php,wordpress")
    paths = [p["path"] for p in r["paths"]]
    assert len(paths) == len(set(paths))


def test_unknown_stack_is_silent():
    r = sensitive_files_list("nonexistent-stack-xyz")
    assert {p["path"] for p in r["paths"]} >= {"/.env"}


def test_invalid_input():
    r = sensitive_files_list(123)  # type: ignore[arg-type]
    assert "error" in r


def test_note_present():
    r = sensitive_files_list()
    assert "authorized testing" in r["note"].lower()
