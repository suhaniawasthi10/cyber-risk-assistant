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
    LLM receives ONLY the structured breakdown — never asset names, CVEs, or actor names."""
    factors = [
        (COMPONENT_LABELS[k], v)
        for k, v in score_breakdown.items()
        if v and v > 0 and k in COMPONENT_LABELS
    ]
    factors.sort(key=lambda x: -x[1])
    factor_lines = "\n".join(f"- {label}: {points} points" for label, points in factors)

    prompt = f"""You write one-sentence plain-English explanations of why a vulnerability scored as it did, from a structured additive scoring breakdown.

PRIORITY ORDER for choosing the LEAD (from the threat report's analyst notes — independent of point counts):
1. internet exposure
2. active exploitation (working exploit, weaponized in current campaigns)
3. ransomware association
4. business criticality and regulatory compliance scope
5. missing compensating controls (e.g. no EDR installed)

Severity / CVSS is a minor capped contributor and MUST NOT lead.

FACTORS THAT CONTRIBUTE TO THIS RISK (you may mention ONLY these):
{factor_lines}

(Raw total: {raw_score}; displayed score capped at 100: {risk_score}.)

STRICT RULES:
1. Mention ONLY factors literally present in the FACTORS list above. If a factor is not in that list, DO NOT mention it. For example, if "ransomware" is not in the FACTORS list, do NOT write any ransomware-related claim, even if other risks would. An absent factor means it is genuinely absent for this risk.
2. Name AT LEAST three of the highest-scoring factors above, by name, in plain language.
3. LEAD with whichever priority-order driver (1-5 above) is present in the FACTORS list. Use that priority order — not raw point count — to choose the lead.
4. DO NOT lead with the underlying vulnerability's severity rating. You may mention severity only as a trailing detail, or omit it.
5. Cite point values inline like "(25)".
6. Do not invent vendors, products, vulnerability names, CVE IDs, or numbers not in the FACTORS list above.
7. Output exactly ONE sentence under 55 words — no preface, no bullets, no numbering.

EXAMPLE (FORMAT-ONLY — your input has DIFFERENT factors; do not assume any factor below is in your input):
Suppose factors were:
- FACTOR-A: 25 points
- FACTOR-B: 20 points
- FACTOR-C: 8 points
A valid output:
"This risk is driven primarily by FACTOR-A (25) and FACTOR-B (20), with FACTOR-C (8) as a secondary contributor."
(Do NOT use placeholder labels in your real output. Use the actual factor names from the FACTORS list above. Do NOT mention any factor not in that list.)

NOW WRITE THE SENTENCE FOR THE FACTORS LIST ABOVE:"""
    return _chat(prompt, max_tokens=200, temperature=0)


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
