import os
from functools import lru_cache

from dotenv import load_dotenv
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer

load_dotenv()

INDEX_NAME = "cyber-risk-nist-800-53"
EMBED_MODEL = "all-MiniLM-L6-v2"


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


def build_query(row):
    vuln = str(row.get("vulnerability_name", "") or "")
    component = str(row.get("affected_component", "") or "")
    return f"{vuln} {component}".strip()


if __name__ == "__main__":
    from app.ingest import load_all
    from app.enrich import build_enriched
    from app.score import score_all, top_n

    scored = score_all(build_enriched(load_all()))
    top = top_n(scored, 5)

    print(f"{'rank':<5}{'asset_id':<10}{'asset_name':<26}{'vulnerability':<48}{'control':<10}{'sim':<6}title")
    print("-" * 160)
    for i, (_, r) in enumerate(top.iterrows(), start=1):
        q = build_query(r)
        c = retrieve_best_control(q)
        print(
            f"{i:<5}"
            f"{r['asset_id']:<10}"
            f"{r['asset_name'][:25]:<26}"
            f"{r['vulnerability_name'][:46]:<48}"
            f"{c['control_id']:<10}"
            f"{c['similarity']:.3f} "
            f"{c['title']}"
        )
        print(f"     query: {q}")
        print()
