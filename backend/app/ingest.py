from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

EXPECTED_ROWS = {
    "assets": 60,
    "vulnerabilities": 114,
    "threat_intelligence": 40,
    "business_services": 20,
    "remediation_guidance": 30,
}


def normalize_cve(value):
    if pd.isna(value):
        return value
    return str(value).strip().upper()


def load_assets():
    return pd.read_csv(DATA_DIR / "assets.csv")


def load_vulnerabilities():
    df = pd.read_csv(DATA_DIR / "vulnerabilities.csv")
    df["cve"] = df["cve"].map(normalize_cve)
    return df


def load_threat_intel():
    df = pd.read_csv(DATA_DIR / "threat_intelligence.csv")
    df["matched_cve_or_control"] = df["matched_cve_or_control"].map(normalize_cve)
    return df


def load_business_services():
    return pd.read_csv(DATA_DIR / "business_services.csv")


def load_remediation_guidance():
    return pd.read_csv(DATA_DIR / "remediation_guidance.csv")


def load_threat_report():
    return (DATA_DIR / "synthetic_threat_report.md").read_text(encoding="utf-8")


def load_all():
    data = {
        "assets": load_assets(),
        "vulnerabilities": load_vulnerabilities(),
        "threat_intelligence": load_threat_intel(),
        "business_services": load_business_services(),
        "remediation_guidance": load_remediation_guidance(),
    }
    for name, expected in EXPECTED_ROWS.items():
        actual = len(data[name])
        assert actual == expected, (
            f"{name}.csv row count mismatch: expected {expected}, got {actual}"
        )
    data["threat_report"] = load_threat_report()
    return data


if __name__ == "__main__":
    data = load_all()
    for name, expected in EXPECTED_ROWS.items():
        print(f"{name:<22} {len(data[name]):>4} rows  (expected {expected})")
    print(f"{'threat_report':<22} {len(data['threat_report'].splitlines()):>4} lines")
