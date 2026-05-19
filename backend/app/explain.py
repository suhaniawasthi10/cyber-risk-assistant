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

    prompt = f"""You will be given a list of factors with their point contributions from a deterministic additive risk-scoring model. Write ONE plain-English sentence (under 40 words) that explains what is driving this risk's score for a business stakeholder.

STRICT RULES:
- Use only the facts in the list. Do not invent.
- Do not mention vendors, products, vulnerability names, CVE IDs, or threat-actor names — those are not in your input.
- Translate any jargon into plain language.
- Lead with the strongest factor.
- Output exactly one sentence, no preface, no bullet list.

Factors (each is a positive contribution):
{factor_lines}

Total raw points: {raw_score}. Displayed score (capped at 100): {risk_score}.
"""
    return _chat(prompt, max_tokens=120)


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
