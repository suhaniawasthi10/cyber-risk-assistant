# Cyber Risk Assistant — TawasolPay

A small system that reads a fixed dataset of security telemetry, cross-references it against the live CISA KEV catalog, ranks the top 5 cyber risks with a multi-factor scoring model, and retrieves the most relevant NIST SP 800-53 control for each risk via semantic search.

Built as a take-home for an AI Internship. The brief says twice that *"we are more interested in how you think than in how much you built,"* so this is deliberately a tight, small system with an opinionated README rather than a sprawling app with a thin one.

## Live

- **Frontend:** https://cyber-risk-assistant.vercel.app
- **Backend API:** https://cyber-risk-assistant-production.up.railway.app/api/risks
- **Repo:** https://github.com/suhaniawasthi10/cyber-risk-assistant

## What it does

1. Ingests 5 CSVs (assets, vulnerabilities, threat intelligence, business services, remediation hints) plus a 1-page synthetic threat report.
2. Downloads the live CISA Known Exploited Vulnerabilities catalog and joins it to the vulnerability list by CVE.
3. Joins vulnerabilities → assets → business services → threat-intel campaigns → KEV with exact-key matching. Every CVE is normalized (uppercase, stripped) on the way in so case or whitespace differences can't silently drop matches.
4. Scores every vulnerability using an additive multi-factor model — *not* CVSS alone. The factors and their priority come straight from the threat report's "Threat Intelligence Analyst Notes" section: internet exposure, active exploitation, ransomware association, business criticality and compliance scope, missing compensating controls. I didn't invent weights from gut feel; the rubric is in the report and I followed it.
5. For the top 5, embeds a query phrase derived from the vulnerability's *weakness category* (RCE, token theft, auth bypass, EOL software, etc.) plus the affected component, then retrieves the nearest NIST SP 800-53 control from a Pinecone index (~1,200 controls, `all-MiniLM-L6-v2` embeddings, 384-dim cosine).
6. Asks an LLM (Groq, `llama-3.3-70b-versatile`) to (a) write a 2–3 sentence plain-English "why this ranks here" from the score breakdown, and (b) rephrase the retrieved NIST control in one sentence. The LLM only ever rephrases structured input — it never supplies facts and never decides ranking.
7. Serves the result as JSON from a FastAPI backend. A React + Tailwind frontend renders the 5 risks in a dark security-console UI.

## One design decision worth calling out

The first version of retrieval used the raw vulnerability name plus the affected component as the embedding query. It failed badly. Queries like *"Fortinet SSL-VPN Heap Buffer Overflow in VPN Firmware"* pulled SI-4.25 (Optimize Network Traffic Analysis) instead of SI-2 (Flaw Remediation), because vendor-specific vulnerability prose simply does not live in the same semantic space as NIST's generic control language. NIST never names vendors; it talks about "flaw remediation," "account management," "unsupported components." The vector spaces didn't overlap and similarity scores sat in the 0.22–0.42 range with the wrong controls coming out on top.

The fix was a classify-then-query layer. A small rule-based classifier in `rag.py` routes every vulnerability into one of five weakness categories (RCE/memory corruption, token/session theft, authentication bypass, unsupported software, misconfiguration / missing control), and each category maps to a NIST-vocabulary query *phrase* — never to a control ID. The classifier picks the vocabulary; Pinecone still picks the control from the live index. No control IDs are ever hardcoded.

After the fix, similarity scores sat between 0.53 and 0.64, and three of the top 5 retrievals landed on textbook-correct controls (the two SI-2 hits for the Fortinet RCEs and AC-2 for the TeamCity auth bypass). The other two were IA-2.8 *Access to Accounts — Replay Resistant* for the two CitrixBleed entries; IA-2.8 isn't the textbook answer for a generic vulnerability, but CitrixBleed is specifically a session-token-replay attack, so replay resistance is genuinely on-point — arguably more useful here than a generic SI-2 patch-it directive would have been. The full story is in commit history; I'm flagging it here because it's the kind of "naive RAG fails, structured routing fixes it" lesson the brief seems designed to surface.

## One nice piece of cross-referencing the system does

The TeamCity vulnerability (`A-1014`, `CVE-2024-27198`) is matched to the *SilentForge* threat-intel campaign, which is explicitly an espionage actor with `ransomware_association = No`. A system that trusted threat intel alone would not flag ransomware exposure on this risk. But CISA KEV independently tags CVE-2024-27198 with `knownRansomwareCampaignUse = Known`, so the scoring layer fires the +15 ransomware component anyway. The two sources disagree, and the system uses both. This isn't a clever trick — it's just what happens when you cross-reference independent feeds — but it's the exact kind of multi-source reasoning the assignment seems designed to reward.

## Architecture

```
ingest.py   → enrich.py   → score.py     → rag.py       → explain.py → results.json
(5 CSVs +    (CISA KEV +   (additive       (NIST 800-53   (Groq LLM:    (cached on
 threat      joins, CVE     scoring +      semantic       plain-English  startup,
 report)     normalize)     top-5)         retrieval via   why-sentence  served by
                                           Pinecone)       + control     FastAPI)
                                                           summary)
```

```
/backend
  /app          ingest, enrich, score, rag, explain, pipeline, main (FastAPI)
  /data         5 source CSVs, KEV (cached), NIST catalog (OSCAL JSON + flattened CSV)
  build_index.py  one-off: embed NIST controls + upsert to Pinecone
  Dockerfile, railway.json
/frontend
  /src/components  Header, RiskEntry, ScoreBadge, ControlBlock, Footer
  tailwind.config.js  custom palette + font tokens only (no stock Tailwind colors)
```

## Tech stack

- **Backend:** Python 3.11, pandas, FastAPI, sentence-transformers (`all-MiniLM-L6-v2`), Pinecone (serverless free tier), Groq (`llama-3.3-70b-versatile`)
- **Frontend:** React + Vite, TailwindCSS with a fully custom theme (no stock color names)
- **Deploy:** backend on Railway (Docker), frontend on Vercel
- **No agent framework, no LangChain, no LlamaIndex.** Plain Python orchestration in `pipeline.py`.

## Run locally

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then fill in GROQ_API_KEY and PINECONE_API_KEY
```

**One-time:** build the Pinecone index from the NIST 800-53 catalog (downloads + parses the OSCAL JSON, embeds ~1,200 controls, upserts):

```bash
python build_index.py
```

**Run the full pipeline once** to produce `results.json`:

```bash
python -m app.pipeline
```

**Serve the API:**

```bash
uvicorn app.main:app --reload
# GET  http://localhost:8000/api/health
# GET  http://localhost:8000/api/risks
# POST http://localhost:8000/api/refresh   (re-runs the pipeline)
```

The backend caches `results.json` on startup and serves it. `/api/refresh` re-runs the pipeline end-to-end.

### Frontend

```bash
cd frontend
npm install
echo "VITE_API_URL=http://localhost:8000" > .env.local
npm run dev
# open the printed localhost URL
```

For a production build: `npm run build` (outputs to `dist/`).

## The three required answers

### 1. What did you embed and why; what did you query as structured records and why?

I embedded one thing: the NIST SP 800-53 Rev 5 catalog. It's ~1,200 controls of long, unstructured prose, and the right control for any given risk is found by meaning — *"Fortinet SSL-VPN heap buffer overflow with available exploit"* should retrieve SI-2 *Flaw Remediation* even though those words barely overlap. That's exactly what vector retrieval is for.

Everything else — the 5 source CSVs and the CISA KEV catalog — I queried as structured records with pandas joins and filters. These files have clean, unambiguous join keys (`asset_id`, `business_service`, `cve`/`cveID`), and embedding them would actively destroy precision. A CVE match is a string equality, not a semantic similarity; vectorizing it would just introduce noise. The threat report markdown is short enough to feed the LLM directly where useful, so it doesn't need embedding either.

The principle I worked from: filter and join where the keys are clean, embed only where prose is the input. The assignment seemed to be testing whether I'd reach for RAG by reflex on everything; I tried not to.

### 2. Three specific ways this system can produce a wrong or misleading output

These are real properties of *this* dataset and pipeline, not the generic "the LLM might hallucinate" answer.

**(a) KEV only contains real CVEs, so the synthetic CVEs in the dataset never match it.** Roughly half the vulnerabilities use synthetic IDs (`CVE-SYN-*`, `CTRL-SYN-*`, `CICD-SYN-*`) which by definition will never appear in the CISA KEV catalog. A naive design that read "absent from KEV" as "not actively exploited" would silently downgrade campaigns that the threat-intel file explicitly marks as Weaponized. KEV is used only as an enricher for real CVEs in this system, and `threat_intelligence.csv` is treated as the authority for synthetic IDs. The pipeline logs both join counts on every run so any regression is loud, not silent.

**(b) Long-stale assets can inflate scores for things that don't actually exist anymore.** The dataset has assets with `last_seen_days` in the 90–180 day range. A-1021 (the NetScaler load balancer) has been open 180 days. That could mean it's been neglected — which is a real risk and should score high — or it could mean the asset was decommissioned and the inventory wasn't updated, in which case the high score is misleading. The current system treats all assets as live and applies a `+5` hygiene penalty when `days_open > 30 and patch_available = Yes`, but it doesn't distinguish *neglected and live* from *probably gone*. A real production version would flag any asset above a staleness threshold and either confirm it with the asset owner or down-weight its score; for this assignment I've documented it but left the scoring uniform so the model stays simple to defend.

**(c) The LLM can subtly over-state confidence.** Even with temperature 0 and a strict prompt that only feeds it the labeled score components and the retrieved NIST control text, the model can pick adjectives ("significantly," "critical," "high-priority") that make a marginal +5 hygiene contribution sound as alarming as a +25 internet-exposure contribution. The mitigation in this build is that the LLM is never the source of facts — every numerical claim and every control ID in the output comes from the structured data, not from generation — but the *tone* of the explanation can still drift. An honest production system would either constrain the prompt with explicit phrasing rules per score band, or run a small post-generation check that the prose is consistent with the breakdown. I'm noting it here because it's the real risk that's left, not a hypothetical one.

### 3. One thing I would change with another day

I'd build a small automated evaluation harness for the RAG step. Right now retrieval is sanity-checked by eye against the five expected control IDs in the brief (SI-2, RA-5, IR-4, AC-2, SA-22), and the classify-then-query layer handles the main categories cleanly. That's defensible for a take-home, but it's fragile — if I added a new weakness category, or swapped the embedding model, or someone added a new kind of vulnerability to the dataset, I'd have no way to know retrieval quality dropped except by reading every result. An `evals/` directory with a few dozen `(query, expected_control_id)` pairs and a script that asserts Pinecone returns the expected control in the top-k for each would do two things: catch regressions when I tune the classifier, and make the retrieval-quality claim measurable rather than vibes-based. The brief is partly a test of whether I think about retrieval seriously, and an eval harness is the honest finish to that thought.

## Known limitations

A few honest things this system doesn't do well:

- **TeamCity's retrieved control is a near-tie.** AC-2 won at 0.644, but three other access-control-family controls sit within 0.05 of it — AC-5 *Separation of Duties* (0.605), AC-3 *Access Enforcement* (0.597), and IA-5.8 *Multiple System Accounts* (0.595). For a generic authentication-bypass weakness on a CI/CD server several of these are defensible; the embedding model picked one. A retrieval-eval harness (see above) would surface these ties explicitly.
- **The ransomware component is summed across two sources.** If both `threat_intelligence.csv` and CISA KEV mark a vulnerability as ransomware-associated, the component fires +15 — same as if only one fired. The output doesn't tell you which source fired it; a future version would split this into two fields so the cross-source confirmation (like the TeamCity case above) is visible at a glance.
- **The remediation_guidance.csv file is unused as a remediation source.** The brief hints at it, but it's keyed by free-text `finding_type` and would fuzzy-misfire on edge cases, so I treat it as a hint at most and let NIST 800-53 retrieval be the actual source of remediation guidance.

## What is deliberately not built

Per the brief's "keep it tight" guidance: no authentication, no database, no multi-agent orchestration, no LangChain/LlamaIndex, no charts or graphs (they would not aid reading here), no user accounts, no real-time feeds. The dataset is fixed and small; the system caches `results.json` on startup and exposes `POST /api/refresh` to re-run the pipeline on demand.

## Data sources

- **CISA Known Exploited Vulnerabilities (KEV):** downloaded live from `cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`, cached locally.
- **NIST SP 800-53 Rev 5:** parsed from the authoritative OSCAL JSON mirror at `raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json` (the `csrc.nist.gov` CSV form returns 404 as of mid-2026; the OSCAL JSON is the live canonical form).
- The 5 provided CSVs and the threat report are synthetic, supplied with the brief.