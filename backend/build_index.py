"""
One-off: download NIST SP 800-53 Rev 5 catalog (OSCAL JSON form), flatten to CSV,
embed each control with all-MiniLM-L6-v2, upsert into Pinecone.
"""
import json
import os
import re
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer

load_dotenv()

BACKEND_DIR = Path(__file__).resolve().parent
DATA_DIR = BACKEND_DIR / "data"
JSON_PATH = DATA_DIR / "nist_800-53.json"
CSV_PATH = DATA_DIR / "nist_800-53.csv"

CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

INDEX_NAME = "cyber-risk-nist-800-53"
EMBED_MODEL = "all-MiniLM-L6-v2"
EMBED_DIM = 384


def download_catalog(force=False):
    if JSON_PATH.exists() and not force:
        return
    r = requests.get(CATALOG_URL, timeout=120)
    r.raise_for_status()
    JSON_PATH.write_bytes(r.content)


def _clean_prose(text):
    if not text:
        return ""
    # OSCAL inline link: [label](#uuid) -> label
    text = re.sub(r"\[([^\]]*)\]\(#[^)]+\)", r"\1", text)
    # OSCAL parameter placeholder: {{ insert: param, ... }} -> [parameter]
    text = re.sub(r"\{\{[^}]*\}\}", "[parameter]", text)
    return text.strip()


def _collect_prose(parts, target_name):
    out = []
    for p in parts or []:
        if p.get("name") == target_name and p.get("prose"):
            out.append(p["prose"])
        if p.get("parts"):
            out.extend(_collect_prose(p["parts"], target_name))
    return _clean_prose(" ".join(out))


def _is_withdrawn(ctrl):
    for prop in ctrl.get("props", []) or []:
        if prop.get("name") == "status" and prop.get("value") == "withdrawn":
            return True
    return False


def _flatten_controls(controls, out):
    for c in controls or []:
        if _is_withdrawn(c):
            continue
        cid = c["id"].upper()
        out.append({
            "control_id": cid,
            "title": c.get("title", ""),
            "control_text": _collect_prose(c.get("parts", []), "statement"),
            "discussion": _collect_prose(c.get("parts", []), "guidance"),
        })
        _flatten_controls(c.get("controls", []), out)


def parse_catalog():
    download_catalog()
    oscal = json.loads(JSON_PATH.read_text())
    rows = []
    for group in oscal["catalog"].get("groups", []):
        _flatten_controls(group.get("controls", []), rows)
    df = pd.DataFrame(rows)
    df.to_csv(CSV_PATH, index=False)
    return df


def build_chunks(df):
    chunks = []
    for _, r in df.iterrows():
        text = f"{r['control_id']}: {r['title']}\n\n{r['control_text']}\n\n{r['discussion']}".strip()
        chunks.append({
            "id": r["control_id"],
            "text": text,
            "title": r["title"],
            "control_text": r["control_text"],
        })
    return chunks


def ensure_index(pc):
    if not pc.has_index(INDEX_NAME):
        pc.create_index(
            name=INDEX_NAME,
            dimension=EMBED_DIM,
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )


def upsert(chunks):
    pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
    ensure_index(pc)
    index = pc.Index(INDEX_NAME)

    model = SentenceTransformer(EMBED_MODEL)
    texts = [c["text"] for c in chunks]
    embeddings = model.encode(texts, show_progress_bar=True, batch_size=32)

    vectors = []
    for c, e in zip(chunks, embeddings):
        vectors.append({
            "id": c["id"],
            "values": e.tolist(),
            "metadata": {
                "control_id": c["id"],
                "title": c["title"],
                # Pinecone caps metadata at 40KB/vector; 4000 chars is safe.
                "text": c["text"][:4000],
            },
        })

    for i in range(0, len(vectors), 100):
        index.upsert(vectors=vectors[i:i + 100])


if __name__ == "__main__":
    df = parse_catalog()
    print(f"parsed {len(df)} controls (base + enhancements, withdrawn excluded)")
    print(f"CSV columns: {list(df.columns)}")
    print(f"CSV cached to: {CSV_PATH}")
    print()
    print("=== sample rows ===")
    print(df.head(3).to_string())
    print()
    chunks = build_chunks(df)
    upsert(chunks)
    print(f"upserted {len(chunks)} vectors to Pinecone index '{INDEX_NAME}'")
