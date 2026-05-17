"""Map a finding / observation to OWASP LLM Top 10 (2025) categories.

Pure rule-based classifier. Keyword and regex patterns per category with
weights; returns ranked matches with the matched evidence per category.

No LLM call. No I/O. Stateless. One observation in, ranked categories out.

Reference: https://genai.owasp.org/llm-top-10/  (Top 10 for LLM Applications 2025)

Part of the Redmai security stack. In production: automatic OWASP-LLM tagging
on every scan finding + compliance reports per ruleset → redmai.io
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]

CATEGORIES: dict[str, dict] = {
    "LLM01": {
        "title": "Prompt Injection",
        "description": "Adversarial input that manipulates an LLM into unintended actions or output.",
        "patterns": [
            (r"\bprompt injection\b", 5),
            (r"\bindirect prompt injection\b", 5),
            (r"\b(ignore|disregard) (the )?(previous|prior|above|all) instructions?\b", 4),
            (r"\bjailbreak\b", 3),
            (r"\bsystem prompt (override|bypass)\b", 4),
            (r"\binstruction[- ]override\b", 3),
            (r"\buntrusted (content|input|document)\b", 2),
            (r"\bmalicious prompt\b", 3),
            (r"\bmissing delimiter\b", 2),
            (r"\btrust[- ]boundary (violation|crossing)\b", 3),
        ],
    },
    "LLM02": {
        "title": "Sensitive Information Disclosure",
        "description": "Model exposes sensitive data: PII, secrets, internal documents, training data leakage.",
        "patterns": [
            (r"\bPII\b", 4),
            (r"\bpersonally identifiable\b", 4),
            (r"\b(api[- ]?key|api token|access token|bearer token)\b", 4),
            (r"\b(secret|password|credential)s?\b leaked", 4),
            (r"\b(secret|password|credential)s?\b (in|inside) (response|output|completion)", 4),
            (r"\btraining data (leak|extraction|memoriz)", 4),
            (r"\bdata exfiltration\b", 3),
            (r"\bredact(ion|ed)?\b", 2),
            (r"\b(SSN|social security)\b", 4),
            (r"\b(credit card|PAN|PCI)\b", 3),
        ],
    },
    "LLM03": {
        "title": "Supply Chain",
        "description": "Compromise of components in the LLM supply chain: models, datasets, plugins, third-party libs.",
        "patterns": [
            (r"\b(malicious|compromised|backdoored) (model|package|dependency|plugin)\b", 5),
            (r"\bmodel (origin|provenance)\b", 3),
            (r"\btypo[- ]?squatt", 4),
            (r"\bdependency confusion\b", 4),
            (r"\b(unsigned|untrusted) (model|weights|checkpoint)\b", 4),
            (r"\bhuggingface (repo|model) (pinned|unpinned|hijack)", 3),
            (r"\bsbom\b", 2),
        ],
    },
    "LLM04": {
        "title": "Data and Model Poisoning",
        "description": "Adversarial manipulation of training/fine-tune data or model weights.",
        "patterns": [
            (r"\b(data|training|dataset) poison", 5),
            (r"\bmodel poison", 5),
            (r"\bbackdoor(ed)? (model|weights)\b", 4),
            (r"\btrigger phrase\b", 3),
            (r"\bfine[- ]?tune.*poison", 4),
            (r"\bRAG poisoning\b", 4),
            (r"\bcorpus contamination\b", 3),
        ],
    },
    "LLM05": {
        "title": "Improper Output Handling",
        "description": "Downstream system blindly trusts LLM output (XSS, SSRF, SQLi, SSTI, command injection from generation).",
        "patterns": [
            (r"\bXSS\b", 4),
            (r"\bcross[- ]site scripting\b", 4),
            (r"\bSSRF\b", 4),
            (r"\bSQL injection\b", 4),
            (r"\bSSTI\b", 4),
            (r"\b(command|code) injection (from|via) (llm|model|generation|output)\b", 4),
            (r"\brendered (unsafely|without (sanitization|escaping))\b", 3),
            (r"\b(eval|exec)\(.*(llm|model|completion|response)", 4),
            (r"\bunescaped (html|markdown|sql)\b", 3),
            (r"\boutput (sanitization|validation|filtering) missing\b", 3),
        ],
    },
    "LLM06": {
        "title": "Excessive Agency",
        "description": "Agent given too much functionality, permission, or autonomy — can take harmful actions.",
        "patterns": [
            (r"\bover[- ]broad (param|permission|scope|tool)\b", 4),
            (r"\b(shell|command) execution (from|via) (agent|tool)\b", 5),
            (r"\bagent (deletes?|writes?|sends?|posts?) (without|with no) (confirmation|approval|human)\b", 4),
            (r"\bunbounded (tool|action) (set|capability)\b", 4),
            (r"\b(arbitrary|unrestricted) (filesystem|network|database) access\b", 4),
            (r"\bagent (auto|automatically) (executes?|runs?)\b", 3),
            (r"\bdisabled (verification|safeguard|confirm)\b", 3),
            (r"\bexcessive (privileges?|permissions?|agency)\b", 5),
        ],
    },
    "LLM07": {
        "title": "System Prompt Leakage",
        "description": "System prompt or its contents (rules, secrets, tool names) revealed to the user.",
        "patterns": [
            (r"\bsystem prompt (leak|disclosure|extraction|exposure)\b", 5),
            (r"\b(print|reveal|repeat|dump|show) (your |the )?system prompt\b", 4),
            (r"\bprompt extraction\b", 4),
            (r"\binternal instructions revealed\b", 3),
            (r"\bsecret in system prompt\b", 4),
        ],
    },
    "LLM08": {
        "title": "Vector and Embedding Weaknesses",
        "description": "Weak access controls, poisoning, or inversion in vector stores / embeddings used by RAG.",
        "patterns": [
            (r"\b(vector|embedding) (store|database)\b", 2),
            (r"\bembedding (inversion|reconstruction)\b", 5),
            (r"\bvector store poison", 5),
            (r"\bRAG (poisoning|context injection)\b", 4),
            (r"\bcross[- ]tenant (vector|embedding|context)\b", 4),
            (r"\bweak (access control|isolation).*vector\b", 3),
        ],
    },
    "LLM09": {
        "title": "Misinformation",
        "description": "Hallucinated or biased model output presented as fact, leading to downstream errors.",
        "patterns": [
            (r"\bhallucinat(ion|ed|es)\b", 4),
            (r"\bconfabulat", 3),
            (r"\bfactually (incorrect|wrong)\b", 3),
            (r"\bfabricated (citation|source|reference|fact)\b", 4),
            (r"\b(bias|biased) (output|generation|completion)\b", 3),
            (r"\bunsourced claim\b", 2),
            (r"\bmodel (confidently )?(wrong|incorrect)\b", 3),
        ],
    },
    "LLM10": {
        "title": "Unbounded Consumption",
        "description": "Lack of rate limits, token caps, or cost controls — DoS or unbounded billing.",
        "patterns": [
            (r"\bDoS\b", 3),
            (r"\bdenial[- ]of[- ]service\b", 3),
            (r"\b(no|missing|absent) (rate limit|token limit|cost cap|budget)\b", 4),
            (r"\bunbounded (token|cost|generation|prompt)\b", 4),
            (r"\b(prompt|input) length unbounded\b", 3),
            (r"\b(infinite|runaway) loop\b", 3),
            (r"\b(resource|cost) exhaustion\b", 4),
            (r"\bbilling abuse\b", 3),
        ],
    },
}


class Match(BaseModel):
    category: str
    title: str
    score: int
    severity: Severity
    evidence: list[str] = Field(default_factory=list)
    description: str


class ClassifyReport(BaseModel):
    input_chars: int
    top_match: str | None
    matches: list[Match] = Field(default_factory=list)
    unmatched: bool = False


def _severity_from_score(score: int) -> Severity:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 2:
        return "low"
    return "info"


def owasp_llm_classify(observation: str, top_n: int = 3) -> dict:
    """Map a finding or observation to OWASP LLM Top 10 (2025) categories.

    Pure rule-based: keyword and regex patterns with weights per category.
    Returns the top `top_n` matching categories with the matched evidence
    snippets and a confidence score.

    Args:
        observation: Free-form text describing a finding, scan result, bug
            report, threat model entry, or security observation.
        top_n: Number of matches to return (default 3).

    Returns:
        ClassifyReport with ranked matches. If nothing matches, `unmatched`
        is True and `matches` is empty.
    """
    if not isinstance(observation, str):
        return {"error": "observation must be a string"}

    report = ClassifyReport(input_chars=len(observation), top_match=None)
    raw_scores: list[Match] = []

    for cat_id, cat in CATEGORIES.items():
        score = 0
        evidence: list[str] = []
        for pattern, weight in cat["patterns"]:
            matches = list(re.finditer(pattern, observation, re.IGNORECASE))
            if matches:
                score += weight * len(matches)
                for m in matches[:2]:
                    snippet = observation[max(0, m.start() - 20):m.end() + 20].strip()
                    snippet = re.sub(r"\s+", " ", snippet)
                    evidence.append(snippet)
        if score > 0:
            raw_scores.append(Match(
                category=cat_id,
                title=cat["title"],
                score=score,
                severity=_severity_from_score(score),
                evidence=evidence,
                description=cat["description"],
            ))

    raw_scores.sort(key=lambda m: m.score, reverse=True)
    report.matches = raw_scores[:max(1, top_n)]
    if not raw_scores:
        report.unmatched = True
    else:
        report.top_match = raw_scores[0].category

    return report.model_dump()
