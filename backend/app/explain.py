import os
from functools import lru_cache

from dotenv import load_dotenv
from groq import Groq

load_dotenv()

MODEL = "llama-3.3-70b-versatile"

# Plain-English labels for the scoring components. The LLM rephrases these
# labels — it never sees the cryptic field names directly.
COMPONENT_LABELS = {
    "cvss_component": "the underlying vulnerability's severity rating",
    "internet_exposure": "the affected asset being directly exposed to the public internet",
    "exploit_component": "a working exploit being available and confirmed in active use",
    "ransomware_component": "the vulnerability being linked to active ransomware campaigns",
    "business_component": "the asset's business criticality and regulatory compliance scope",
    "controls_component": "the absence of endpoint detection on the affected asset",
    "hygiene_component": "the vulnerability remaining unpatched for an extended period",
}


@lru_cache(maxsize=1)
def _client():
    return Groq(api_key=os.environ["GROQ_API_KEY"])


def _chat(prompt, max_tokens=120, temperature=0.2):
    response = _client().chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content.strip()


def explain_score(score_breakdown, raw_score, risk_score):
    """One sentence narrating which factors drive the score.
    LLM receives ONLY the structured breakdown — never asset names, CVEs, or actor names.
    Every factor with ≥8 points must be named explicitly; catch-all phrases forbidden."""
    factors = [
        (COMPONENT_LABELS[k], v)
        for k, v in score_breakdown.items()
        if v and v > 0 and k in COMPONENT_LABELS
    ]
    factors.sort(key=lambda x: -x[1])

    required = [(label, p) for label, p in factors if p >= 8]
    optional = [(label, p) for label, p in factors if 0 < p < 8]

    required_lines = "\n".join(f"- {label}: {p} points" for label, p in required)
    optional_lines = (
        "\n".join(f"- {label}: {p} points" for label, p in optional)
        if optional else "(none)"
    )

    prompt = f"""You write one-sentence plain-English explanations of why a vulnerability scored as it did, from a structured additive scoring breakdown.

PRIORITY ORDER for choosing the LEAD (from the threat report's analyst notes — independent of point counts):
1. internet exposure
2. active exploitation (working exploit, weaponized in current campaigns)
3. ransomware association
4. business criticality and regulatory compliance scope
5. missing compensating controls (e.g. no EDR installed)

Severity / CVSS is a minor capped contributor and MUST NOT lead.

REQUIRED FACTORS (your sentence MUST name every single one of these, each with its point value):
{required_lines}

OPTIONAL FACTORS (you may include or omit; if included, name explicitly with value — never a catch-all):
{optional_lines}

(Raw total: {raw_score}; displayed score capped at 100: {risk_score}.)

STRICT RULES:
1. Your sentence MUST name every label from REQUIRED FACTORS, each with its point value in parentheses like "(25)". Do not skip any.
2. FORBIDDEN PHRASES (never use any of these): "other factors", "additional contributors", "and more", "etc.", "and others", "various factors", "among other things", "and so on". Every factor cited must be explicitly named.
3. You may include OPTIONAL FACTORS by name with their point value, or omit them entirely. If included, name them; never refer with a catch-all.
4. Do NOT mention any factor that is not in REQUIRED or OPTIONAL above.
5. LEAD with whichever priority-order driver (1-5 above) is present in REQUIRED FACTORS. Use that priority order, not raw point count.
6. DO NOT lead with the underlying vulnerability's severity rating. Severity is a minor capped contributor; you may mention it only as a trailing detail.
7. Do not invent vendors, products, vulnerability names, CVE IDs, or numbers not in the lists above.
8. Output exactly ONE sentence — no preface, no bullets, no numbering. May be up to ~80 words to fit all required factors.

EXAMPLE (FORMAT-ONLY — your input has DIFFERENT factors; do not copy these labels):
If REQUIRED were:
- FACTOR-A: 25 points
- FACTOR-B: 25 points
- FACTOR-C: 15 points
- FACTOR-D: 18 points
- FACTOR-E: 8 points
- FACTOR-F: 29 points
And OPTIONAL were:
- FACTOR-G: 5 points
A valid output (names every REQUIRED factor, optionally includes FACTOR-G):
"This risk is driven by FACTOR-A (25) and FACTOR-B (25), compounded by FACTOR-D (18), FACTOR-C (15), and FACTOR-E (8), on top of FACTOR-F (29) and a minor FACTOR-G (5) contribution."

NOW WRITE THE SENTENCE FOR THE REQUIRED + OPTIONAL FACTORS ABOVE:"""
    return _chat(prompt, max_tokens=300, temperature=0)


def explain_control(control_id, title, text):
    """One sentence rephrasing the NIST control text. LLM rephrases only."""
    prompt = f"""Summarize this NIST 800-53 control in ONE plain-English sentence (under 30 words) for a business stakeholder.

STRICT RULES:
- Use only the text below. Do not invent examples or details.
- Do not name standards, CVEs, vendors, or technologies.
- Restate what the control requires the organization to do, in everyday language.
- Do not preface ("This control says..."). Just write the sentence.

Control title: {title}

Control text:
{text}
"""
    return _chat(prompt, max_tokens=100)
