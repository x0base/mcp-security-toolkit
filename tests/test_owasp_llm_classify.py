from mcp_security_toolkit.tools.owasp_llm_classify import owasp_llm_classify


def test_prompt_injection_match():
    r = owasp_llm_classify("Attacker uses prompt injection to make the model ignore previous instructions.")
    assert r["top_match"] == "LLM01"


def test_sensitive_info_disclosure():
    r = owasp_llm_classify("Response leaked an api_key and PII in the completion.")
    assert r["top_match"] == "LLM02"


def test_supply_chain():
    r = owasp_llm_classify("We loaded a backdoored model from an unsigned HuggingFace repo.")
    assert r["top_match"] == "LLM03"


def test_data_poisoning():
    r = owasp_llm_classify("Adversary performed data poisoning on the fine-tune corpus.")
    assert r["top_match"] == "LLM04"


def test_improper_output_handling():
    r = owasp_llm_classify("Frontend renders model output as unescaped HTML — classic XSS.")
    assert r["top_match"] == "LLM05"


def test_excessive_agency():
    r = owasp_llm_classify("Agent has over-broad tool with shell execution from a single user message.")
    assert r["top_match"] == "LLM06"


def test_system_prompt_leakage():
    r = owasp_llm_classify("User got the model to reveal the system prompt via prompt extraction.")
    assert r["top_match"] == "LLM07"


def test_vector_embedding_weakness():
    r = owasp_llm_classify("RAG poisoning attack against the vector store across tenants.")
    assert r["top_match"] == "LLM08"


def test_misinformation():
    r = owasp_llm_classify("Model produced a fabricated citation and a hallucination presented as fact.")
    assert r["top_match"] == "LLM09"


def test_unbounded_consumption():
    r = owasp_llm_classify("No rate limit on the endpoint — denial-of-service via unbounded tokens.")
    assert r["top_match"] == "LLM10"


def test_unmatched():
    r = owasp_llm_classify("The weather is nice today.")
    assert r["unmatched"] is True
    assert r["matches"] == []


def test_top_n_respected():
    r = owasp_llm_classify(
        "Prompt injection caused the model to leak api_key and the system prompt.",
        top_n=2,
    )
    assert len(r["matches"]) <= 2


def test_evidence_returned():
    r = owasp_llm_classify("Prompt injection abused the tool.")
    assert r["matches"][0]["evidence"]


def test_severity_scales_with_score():
    weak = owasp_llm_classify("PII")  # one weak hit
    strong = owasp_llm_classify("PII leaked, api_key in response, credentials in output, SSN exposure")
    assert weak["matches"][0]["score"] < strong["matches"][0]["score"]


def test_multiple_matches_returned():
    r = owasp_llm_classify(
        "Prompt injection caused the agent's shell execution tool to fire — excessive agency plus injection.",
        top_n=3,
    )
    cats = {m["category"] for m in r["matches"]}
    assert "LLM01" in cats
    assert "LLM06" in cats


def test_non_string_input():
    r = owasp_llm_classify(None)  # type: ignore[arg-type]
    assert "error" in r
