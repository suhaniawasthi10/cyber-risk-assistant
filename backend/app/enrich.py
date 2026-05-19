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

    ti_unique = ti.drop_duplicates("matched_cve_or_control", keep="first")
    merged = merged.merge(
        ti_unique,
        left_on="cve",
        right_on="matched_cve_or_control",
        how="left",
    )

    kev_unique = kev.drop_duplicates("cveID", keep="first")[
        ["cveID", "knownRansomwareCampaignUse", "dateAdded"]
    ]
    merged = merged.merge(kev_unique, left_on="cve", right_on="cveID", how="left")

    return merged


def report_match_counts(data, enriched):
    ti = data["threat_intelligence"]
    matched_ti_ids = set(enriched.dropna(subset=["intel_id"])["intel_id"].unique())
    matched = len(matched_ti_ids)
    unmatched = len(ti) - matched

    vuln_ti_hits = enriched["intel_id"].notna().sum()
    vuln_kev_hits = enriched["cveID"].notna().sum()

    # context.md §6: treat assets.internet_exposed as authoritative; log disagreements.
    disagree = enriched[
        ((enriched["internet_exposed"] == "Yes") & (enriched["asset_exposure"] != "Internet"))
        | ((enriched["internet_exposed"] == "No") & (enriched["asset_exposure"] == "Internet"))
    ]

    print(f"threat_intel rows matched     : {matched} / {len(ti)}")
    print(f"threat_intel rows unmatched   : {unmatched} / {len(ti)}  (industry noise)")
    print(f"vulnerabilities with TI hit   : {vuln_ti_hits} / {len(enriched)}")
    print(f"vulnerabilities with KEV hit  : {vuln_kev_hits} / {len(enriched)}")
    print(f"exposure-field disagreements  : {len(disagree)}")


if __name__ == "__main__":
    data = load_all()
    enriched = build_enriched(data)
    report_match_counts(data, enriched)
    print(f"enriched rows: {len(enriched)}")
