from pathlib import Path
import pandas as pd
import requests

from app.ingest import DATA_DIR, load_all, normalize_cve

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
KEV_PATH = DATA_DIR / "kev.csv"


def download_kev(force=False):
    if KEV_PATH.exists() and not force:
        return
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    KEV_PATH.write_bytes(r.content)


def load_kev():
    download_kev()
    df = pd.read_csv(KEV_PATH)
    df["cveID"] = df["cveID"].map(normalize_cve)
    return df


def build_enriched(data):
    vulns = data["vulnerabilities"]
    assets = data["assets"]
    services = data["business_services"]
    ti = data["threat_intelligence"]
    kev = load_kev()

    merged = vulns.merge(assets, on="asset_id", how="left")
    merged = merged.merge(services, on="business_service", how="left")

    # Do NOT pre-dedupe ti on matched_cve_or_control. Two TI rows may legitimately
    # target the same CVE (e.g., two campaigns), and we want both counted in the
    # match-rate logging. asset-dedup in score.top_n collapses any per-asset dupes.
    merged = merged.merge(
        ti,
        left_on="cve",
        right_on="matched_cve_or_control",
        how="left",
    )

    kev_unique = kev.drop_duplicates("cveID", keep="first")[
        ["cveID", "knownRansomwareCampaignUse", "dateAdded"]
    ]
    merged = merged.merge(kev_unique, left_on="cve", right_on="cveID", how="left")

    return merged


def report_match_counts(data, enriched, verbose=True):
    ti = data["threat_intelligence"]
    matched_ti_ids = set(enriched.dropna(subset=["intel_id"])["intel_id"].unique())
    matched = len(matched_ti_ids)
    unmatched = len(ti) - matched

    vuln_ti_hits = int(enriched["intel_id"].notna().sum())
    vuln_kev_hits = int(enriched["cveID"].notna().sum())

    # context.md §6: treat assets.internet_exposed as authoritative; log disagreements.
    disagree = enriched[
        ((enriched["internet_exposed"] == "Yes") & (enriched["asset_exposure"] != "Internet"))
        | ((enriched["internet_exposed"] == "No") & (enriched["asset_exposure"] == "Internet"))
    ]

    counts = {
        "threat_intel_total": len(ti),
        "threat_intel_matched": matched,
        "threat_intel_unmatched": unmatched,
        "vulnerabilities_with_ti_hit": vuln_ti_hits,
        "vulnerabilities_with_kev_hit": vuln_kev_hits,
        "exposure_field_disagreements": int(len(disagree)),
    }
    if verbose:
        print(f"threat_intel rows matched     : {matched} / {len(ti)}")
        print(f"threat_intel rows unmatched   : {unmatched} / {len(ti)}  (industry noise)")
        print(f"vulnerabilities with TI hit   : {vuln_ti_hits} / {len(enriched)}")
        print(f"vulnerabilities with KEV hit  : {vuln_kev_hits} / {len(enriched)}")
        print(f"exposure-field disagreements  : {len(disagree)}")
    return counts


if __name__ == "__main__":
    data = load_all()
    enriched = build_enriched(data)
    report_match_counts(data, enriched)
    print(f"enriched rows: {len(enriched)}")
