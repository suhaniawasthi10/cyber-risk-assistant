"""
Orchestrate ingest → enrich → score → top-5 → retrieve NIST control → LLM prose.
Writes results.json for the API to serve.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from app.ingest import load_all
from app.enrich import build_enriched, report_match_counts
from app.score import score_all, top_n
from app.rag import retrieve_for_risk
from app.explain import explain_score, explain_control

BACKEND_DIR = Path(__file__).resolve().parent.parent
RESULTS_PATH = BACKEND_DIR / "results.json"

SCORE_COMPONENT_KEYS = [
    "cvss_component", "internet_exposure", "exploit_component",
    "ransomware_component", "business_component",
    "controls_component", "hygiene_component",
]


def _clean(value):
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(value, "item"):
        return value.item()
    return value


def _build_entry(rank, row, retrieval):
    breakdown = {k: float(row[k]) for k in SCORE_COMPONENT_KEYS}

    entry = {
        "rank": rank,
        "risk_score": float(row["risk_score"]),
        "raw_score": float(row["raw_score"]),
        "score_breakdown": breakdown,
        "asset": {
            "asset_id": _clean(row.get("asset_id")),
            "asset_name": _clean(row.get("asset_name")),
            "asset_type": _clean(row.get("asset_type")),
            "environment": _clean(row.get("environment")),
            "owner_team": _clean(row.get("owner_team")),
            "internet_exposed": _clean(row.get("internet_exposed")),
            "criticality": _clean(row.get("criticality")),
            "edr_installed": _clean(row.get("edr_installed")),
            "vendor_product": _clean(row.get("vendor_product")),
            "location": _clean(row.get("location")),
        },
        "vulnerability": {
            "vuln_id": _clean(row.get("vuln_id")),
            "vulnerability_name": _clean(row.get("vulnerability_name")),
            "cve": _clean(row.get("cve")),
            "severity": _clean(row.get("severity")),
            "cvss": _clean(row.get("cvss")),
            "affected_component": _clean(row.get("affected_component")),
            "days_open": _clean(row.get("days_open")),
            "patch_available": _clean(row.get("patch_available")),
            "exploit_available": _clean(row.get("exploit_available")),
        },
        "threat_intel": None if pd.isna(row.get("intel_id")) else {
            "intel_id": _clean(row.get("intel_id")),
            "threat_actor": _clean(row.get("threat_actor")),
            "campaign_name": _clean(row.get("campaign_name")),
            "exploit_maturity": _clean(row.get("exploit_maturity")),
            "ransomware_association": _clean(row.get("ransomware_association")),
            "confidence": _clean(row.get("confidence")),
            "target_sector": _clean(row.get("target_sector")),
            "target_region": _clean(row.get("target_region")),
            "summary": _clean(row.get("summary")),
        },
        "kev": None if pd.isna(row.get("cveID")) else {
            "in_kev": True,
            "known_ransomware_campaign_use": _clean(row.get("knownRansomwareCampaignUse")),
            "date_added": _clean(row.get("dateAdded")),
        },
        "business_service": {
            "name": _clean(row.get("business_service")),
            "business_owner": _clean(row.get("business_owner")),
            "business_impact": _clean(row.get("business_impact")),
            "customer_facing": _clean(row.get("customer_facing")),
            "compliance_scope": _clean(row.get("compliance_scope")),
            "revenue_impact": _clean(row.get("revenue_impact")),
        },
        "nist_control": {
            "control_id": retrieval["control"]["control_id"],
            "title": retrieval["control"]["title"],
            "similarity": retrieval["control"]["similarity"],
            "weakness_category": retrieval["category"],
            "query_phrase": retrieval["query"],
        },
    }
    return entry


def run(verbose=True):
    if verbose:
        print("=== ingest ===")
    data = load_all()
    if verbose:
        print(f"  loaded {sum(len(data[k]) for k in ['assets','vulnerabilities','threat_intelligence','business_services','remediation_guidance'])} rows across 5 CSVs")
        print("\n=== enrich ===")
    enriched = build_enriched(data)
    counts = report_match_counts(data, enriched, verbose=verbose)

    if verbose:
        print("\n=== score + top-5 ===")
    scored = score_all(enriched)
    top = top_n(scored, 5)
    if verbose:
        for _, r in top.iterrows():
            print(f"  {r['asset_id']:<8} raw={r['raw_score']:>6.1f}  {r['vulnerability_name']}")

    if verbose:
        print("\n=== retrieve NIST controls + LLM prose ===")
    entries = []
    for rank, (_, row) in enumerate(top.iterrows(), start=1):
        retrieval = retrieve_for_risk(row)
        entry = _build_entry(rank, row, retrieval)

        # LLM prose: rephrases structured input only.
        entry["why_sentence"] = explain_score(
            entry["score_breakdown"], entry["raw_score"], entry["risk_score"]
        )
        entry["nist_control"]["summary"] = explain_control(
            entry["nist_control"]["control_id"],
            entry["nist_control"]["title"],
            retrieval["control"]["text"],
        )

        entries.append(entry)
        if verbose:
            ctrl = entry["nist_control"]
            print(f"  #{rank} {row['asset_id']} → {ctrl['control_id']} {ctrl['title']} (sim {ctrl['similarity']:.3f})")

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_quality": counts,
        "risks": entries,
    }
    RESULTS_PATH.write_text(json.dumps(result, indent=2))
    if verbose:
        print(f"\nwrote {RESULTS_PATH}")
    return result


if __name__ == "__main__":
    run()
