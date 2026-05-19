import os
import re
from functools import lru_cache

from dotenv import load_dotenv
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer

load_dotenv()

INDEX_NAME = "cyber-risk-nist-800-53"
EMBED_MODEL = "all-MiniLM-L6-v2"


# Rule-based weakness classifier. Each rule maps surface keywords found in the
# vulnerability name / affected component to a NIST-vocabulary query phrase.
# Rules are walked in order; first match wins. NO NIST control IDs appear in
# this table — only vocabulary. Pinecone still chooses the actual control.
WEAKNESS_RULES = [
    (
        "rce_memory_corruption",
        (
            "rce", "remote code execution",
            "buffer overflow", "heap overflow", "stack overflow", "heap buffer",
            "memory corruption", "use after free",
            "deserialization", "object injection", "template injection",
            "command injection", "code injection", "argument injection",
            "path traversal", "directory traversal", "ognl",
            "sql injection",
        ),
        "flaw remediation and security patch management for exploitable software vulnerability",
    ),
    (
        "unsupported_eol",
        (
            "unsupported", "end of life", "end-of-life", "eol",
            "deprecated", "outdated", "legacy", "obsolete",
        ),
        "unsupported system components and replacement of end-of-life software",
    ),
    (
        "missing_control",
        (
            "missing edr", "no edr", "missing mfa", "no mfa",
            "missing encryption", "no encryption",
            "missing logging", "no logging", "no monitoring", "no antivirus",
            "missing http security headers", "missing security headers",
            "insufficient", "lacking",
        ),
        "vulnerability monitoring and continuous security control assessment",
    ),
    (
        "misconfiguration",
        (
            "misconfiguration", "misconfigured",
            "exposed admin", "exposed management", "exposed interface",
            "exposed api", "admin api exposed", "management plane",
            "publicly accessible", "open port", "default config",
            "internet-exposed", "internet exposed",
            "weak admin password", "weak password policy",
            "outdated tls",
        ),
        "configuration management and secure baseline settings",
    ),
    (
        "authentication_access",
        (
            "authentication bypass", "auth bypass",
            "session token", "session leak", "session hijack",
            "access control", "broken access", "broken authentication",
            "insecure direct object", "idor",
            "credential", "default password",
        ),
        "account management and access enforcement for authentication weakness",
    ),
]

DEFAULT_CATEGORY = "uncategorized_flaw"
DEFAULT_PHRASE = "flaw remediation and patch management for software vulnerability"


def classify(vulnerability_name, affected_component=""):
    """Return (category_id, query_phrase). First matching rule wins."""
    text = f"{vulnerability_name or ''} {affected_component or ''}".lower()
    for category, keywords, phrase in WEAKNESS_RULES:
        for kw in keywords:
            # word-boundary match so "rce" doesn't match inside "force"
            if re.search(r"\b" + re.escape(kw) + r"\b", text):
                return category, phrase
    return DEFAULT_CATEGORY, DEFAULT_PHRASE


def build_query(vulnerability_name, affected_component):
    category, phrase = classify(vulnerability_name, affected_component)
    component = (affected_component or "").strip()
    query = f"{phrase} for {component}" if component else phrase
    return category, query


@lru_cache(maxsize=1)
def _model():
    return SentenceTransformer(EMBED_MODEL)


@lru_cache(maxsize=1)
def _index():
    pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
    return pc.Index(INDEX_NAME)


def retrieve_best_control(query, top_k=1):
    embedding = _model().encode([query])[0].tolist()
    result = _index().query(vector=embedding, top_k=top_k, include_metadata=True)
    matches = result.get("matches", []) if isinstance(result, dict) else result.matches
    if not matches:
        return None
    m = matches[0]
    meta = m["metadata"] if isinstance(m, dict) else m.metadata
    score = m["score"] if isinstance(m, dict) else m.score
    return {
        "control_id": meta.get("control_id"),
        "title": meta.get("title"),
        "text": meta.get("text"),
        "similarity": float(score),
    }


def retrieve_for_risk(row):
    vuln = str(row.get("vulnerability_name", "") or "")
    component = str(row.get("affected_component", "") or "")
    category, query = build_query(vuln, component)
    control = retrieve_best_control(query)
    return {"category": category, "query": query, "control": control}


if __name__ == "__main__":
    from app.ingest import load_all
    from app.enrich import build_enriched
    from app.score import score_all, top_n

    scored = score_all(build_enriched(load_all()))
    top = top_n(scored, 5)

    print("=== Phase 2 retrieval gate ===")
    print()
    for i, (_, r) in enumerate(top.iterrows(), start=1):
        res = retrieve_for_risk(r)
        c = res["control"]
        print(f"#{i}  {r['asset_id']}  {r['asset_name']}")
        print(f"     vuln       : {r['vulnerability_name']}")
        print(f"     component  : {r['affected_component']}")
        print(f"     category   : {res['category']}")
        print(f"     query      : {res['query']}")
        print(f"     retrieved  : {c['control_id']}  —  {c['title']}")
        print(f"     similarity : {c['similarity']:.3f}")
        print()
