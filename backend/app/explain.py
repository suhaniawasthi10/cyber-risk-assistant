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
    """A short analyst-style note (2-3 sentences) explaining what drives the risk.
    No inline point values in the prose — the structured breakdown shows those separately.
    Same input gives same output at temperature 0; that's correct because two risks
    with identical breakdowns genuinely deserve similar explanations."""
    factors = [
        (COMPONENT_LABELS[k], v)
        for k, v in score_breakdown.items()
        if v and v > 0 and k in COMPONENT_LABELS
    ]
    factors.sort(key=lambda x: -x[1])
    factor_lines = "\n".join(f"- {label} (weight: {p})" for label, p in factors)

    prompt = f"""You write short security-analyst notes explaining why a vulnerability scored as it did, in plain English a non-technical executive can read.

PRIORITY ORDER for the LEAD (independent of point counts):
1. internet exposure
2. active exploitation (working exploit, weaponized in current campaigns)
3. ransomware association
4. business criticality and regulatory compliance scope
5. missing compensating controls (e.g. no EDR installed)

Severity / CVSS is a minor capped factor. You may OMIT it from the prose entirely if the note reads better without it.

FACTORS PRESENT FOR THIS RISK (the weight numbers are for YOUR reference only — DO NOT put them into the prose):
{factor_lines}

YOUR TASK: Write 2 OR 3 short sentences, in the voice of a security analyst writing a brief, like an investigation note.

STRICT RULES:
1. NO numeric values inside the prose. No "(25)", no "(15)", no "(29.4)". The exact scores live in a structured block elsewhere on the page; the prose must NOT repeat them. If you write any number in parentheses you have broken this rule.
2. Name the genuinely significant factors that are present in the FACTORS list — typically internet exposure, active exploitation, ransomware linkage, missing EDR, business/compliance criticality — in plain words. You do NOT need to mention every factor; pick what genuinely explains the score.
3. Mention ONLY factors that appear in the FACTORS list above. Do not invent factors. If ransomware isn't in the list, don't mention ransomware.
4. DO NOT lead with the underlying vulnerability's severity rating. Severity can be omitted entirely.
5. Do NOT use a rigid template like "This risk is driven by X, compounded by Y". Avoid catch-all phrases such as "other factors", "additional contributors", "and more", "etc.", "various factors".
6. Write 2 OR 3 short, declarative sentences. No bullets, no numbering, no preface. Conversational, not robotic.
7. Do not invent vendors, products, vulnerability names, or CVE IDs.

EXAMPLE (one illustrative style; you are not required to copy this structure):
Public-facing asset with a known-exploited vulnerability and active ransomware-campaign linkage. The host lacks endpoint detection and the affected service carries regulated, customer-critical load.

NOW WRITE THE NOTE FOR THE FACTORS LIST ABOVE:"""
    return _chat(prompt, max_tokens=250, temperature=0)


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
