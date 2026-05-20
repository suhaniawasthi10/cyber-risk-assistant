import { useEffect, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL

export default function App() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch(`${API_URL}/api/risks`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(setData)
      .catch((e) => setError(e.message))
  }, [])

  if (error) return <pre>error: {error}</pre>
  if (!data) return <p>Loading…</p>

  return (
    <main>
      <h1>TawasolPay — Top 5 Cyber Risks</h1>
      <p>generated_at: {data.generated_at}</p>

      {data.risks.map((r) => (
        <section key={r.rank} style={{ borderTop: '1px solid #ccc', padding: '12px 0' }}>
          <h2>#{r.rank} — score {r.risk_score} (raw {r.raw_score})</h2>

          <p><b>Asset:</b> {r.asset.asset_id} {r.asset.asset_name} ({r.asset.asset_type}, {r.asset.environment}) — owner: {r.asset.owner_team} — internet_exposed: {r.asset.internet_exposed} — criticality: {r.asset.criticality} — edr: {r.asset.edr_installed}</p>

          <p><b>Vulnerability:</b> {r.vulnerability.vulnerability_name} — {r.vulnerability.cve} — CVSS {r.vulnerability.cvss} — component: {r.vulnerability.affected_component} — days_open: {r.vulnerability.days_open}</p>

          {r.threat_intel && (
            <p><b>Threat intel:</b> {r.threat_intel.threat_actor} / {r.threat_intel.campaign_name} — maturity: {r.threat_intel.exploit_maturity} — ransomware: {r.threat_intel.ransomware_association}</p>
          )}

          <p><b>Business service:</b> {r.business_service.name} — owner: {r.business_service.business_owner} — compliance: {r.business_service.compliance_scope}</p>

          <p><b>Why:</b> {r.why_sentence}</p>

          <p><b>NIST control:</b> {r.nist_control.control_id} — {r.nist_control.title}<br />{r.nist_control.summary}</p>
        </section>
      ))}
    </main>
  )
}
