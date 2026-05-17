from mcp_security_toolkit.tools.wordlist_gen import wordlist_gen


def test_passwords_basic():
    r = wordlist_gen(mode="passwords", brand="Acme", keywords=["widget"], years=["2024"])
    assert r["total"] > 10
    assert "acme" in r["sample"]
    assert any("2024" in w for w in r["sample"])


def test_passwords_includes_leet():
    r = wordlist_gen(mode="passwords", brand="secure")
    assert any("$" in w or "3" in w or "0" in w for w in r["sample"])


def test_usernames_patterns():
    r = wordlist_gen(mode="usernames", names=["Jane Doe", "John Smith"])
    sample = set(r["sample"])
    assert "jane.doe" in sample
    assert "jdoe" in sample
    assert "janed" in sample
    assert "doe.jane" in sample


def test_usernames_requires_names():
    r = wordlist_gen(mode="usernames")
    assert "error" in r


def test_subdomains_includes_common_env_labels():
    r = wordlist_gen(mode="subdomains", brand="acme")
    sample = set(r["sample"])
    assert "dev" in sample
    assert "staging" in sample
    assert "acme-dev" in sample or "dev-acme" in sample


def test_subdomains_requires_brand():
    r = wordlist_gen(mode="subdomains")
    assert "error" in r


def test_invalid_mode():
    r = wordlist_gen(mode="bogus")  # type: ignore[arg-type]
    assert "error" in r


def test_max_size_caps_output():
    r = wordlist_gen(mode="passwords", brand="x", keywords=["a", "b", "c"], max_size=5)
    assert len(r["sample"]) <= 5
    if r["total"] > 5:
        assert r["truncated"] is True


def test_sorted_and_unique():
    r = wordlist_gen(mode="passwords", brand="test")
    assert r["sample"] == sorted(set(r["sample"]))
