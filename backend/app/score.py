import pandas as pd

CRITICALITY_POINTS = {"Critical": 18, "High": 8, "Medium": 3, "Low": 0}
WEAPONIZED_LABELS = {"Weaponized", "Active Exploitation"}


def _yes(v):
    return str(v).strip().lower() == "yes"


def _cvss_component(row):
    try:
        return min(30.0, float(row["cvss"]) * 3.0)
    except (TypeError, ValueError):
        return 0.0


def _internet_exposure_component(row):
    return 25 if _yes(row.get("internet_exposed")) else 0


def _exploit_component(row):
    score = 10 if _yes(row.get("exploit_available")) else 0
    if pd.notna(row.get("cveID")):
        score += 5
    if str(row.get("exploit_maturity", "")).strip() in WEAPONIZED_LABELS:
        score += 10
    return score


def _ransomware_component(row):
    ti_match = _yes(row.get("ransomware_association"))
    kev_match = str(row.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
    return 15 if (ti_match or kev_match) else 0


def _business_component(row):
    crit = str(row.get("criticality", "")).strip()
    score = CRITICALITY_POINTS.get(crit, 0)
    scope = str(row.get("compliance_scope", "") or "")
    if "PCI DSS" in scope or "GDPR" in scope:
        score += 5
    return score


def _controls_component(row):
    return 8 if not _yes(row.get("edr_installed")) else 0


def _hygiene_component(row):
    if not _yes(row.get("patch_available")):
        return 0
    try:
        return 5 if int(row.get("days_open", 0)) > 30 else 0
    except (TypeError, ValueError):
        return 0


def score_row(row):
    components = {
        "cvss_component": _cvss_component(row),
        "internet_exposure": _internet_exposure_component(row),
        "exploit_component": _exploit_component(row),
        "ransomware_component": _ransomware_component(row),
        "business_component": _business_component(row),
        "controls_component": _controls_component(row),
        "hygiene_component": _hygiene_component(row),
    }
    raw = sum(components.values())
    components["raw_score"] = round(raw, 1)
    components["risk_score"] = round(min(100.0, raw), 1)
    return components


def score_all(enriched):
    scores = enriched.apply(score_row, axis=1, result_type="expand")
    return pd.concat(
        [enriched.reset_index(drop=True), scores.reset_index(drop=True)], axis=1
    )


def top_n(scored, n=5):
    # Rank by raw_score so true severity beats the 0-100 cap. Dedupe by asset so
    # each entry represents one host's worst risk (context.md §10).
    ordered = scored.sort_values("raw_score", ascending=False, kind="stable")
    by_asset = ordered.drop_duplicates("asset_id", keep="first")
    return by_asset.head(n)


if __name__ == "__main__":
    from app.ingest import load_all
    from app.enrich import build_enriched

    data = load_all()
    enriched = build_enriched(data)
    scored = score_all(enriched)
    top = top_n(scored, 5)

    display_cols = [
        "asset_id", "asset_name", "vulnerability_name", "cve", "cvss",
        "risk_score", "internet_exposed", "criticality", "campaign_name",
        "exploit_maturity", "ransomware_association",
    ]
    print(top[display_cols].to_string(index=False))
