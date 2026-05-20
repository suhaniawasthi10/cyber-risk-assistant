import ScoreBadge from './ScoreBadge'
import ControlBlock from './ControlBlock'

function pad2(n) {
  return String(n).padStart(2, '0')
}

function joinParts(parts) {
  return parts.filter(Boolean).join(' · ')
}

export default function RiskEntry({ risk }) {
  const { rank, risk_score, asset, vulnerability, threat_intel, business_service, why_sentence, nist_control } = risk

  const assetLine = joinParts([
    asset.asset_id,
    asset.asset_name,
    asset.asset_type,
    asset.environment,
    asset.location,
  ])
  const vulnLine = joinParts([
    vulnerability.cve,
    vulnerability.cvss != null && `CVSS ${vulnerability.cvss}`,
    vulnerability.vulnerability_name,
  ])
  const intelLine = threat_intel
    ? joinParts([
        `${threat_intel.threat_actor} / ${threat_intel.campaign_name}`,
        threat_intel.exploit_maturity,
        threat_intel.ransomware_association === 'Yes' && 'ransomware-linked',
      ])
    : null
  const serviceLine = joinParts([
    business_service.name,
    business_service.compliance_scope,
    business_service.revenue_impact && `${business_service.revenue_impact} revenue impact`,
  ])

  return (
    <article className="border-t border-line py-10">
      <div className="flex items-start justify-between gap-6">
        <div className="flex items-baseline gap-5">
          <span className="font-mono text-3xl text-muted leading-none">{pad2(rank)}</span>
          <h2 className="text-lg font-semibold leading-snug">{asset.asset_name}</h2>
        </div>
        <ScoreBadge score={risk_score} />
      </div>

      <dl className="mt-6 kv-grid">
        <dt className="kv-label">asset</dt>
        <dd className="text-ink">
          <span className="font-mono">{asset.asset_id}</span>
          <span className="text-muted"> · </span>
          {joinParts([asset.asset_name, asset.asset_type, asset.environment, asset.location])}
          {asset.internet_exposed === 'Yes' && (
            <span className="text-critical"> · internet-exposed</span>
          )}
          {asset.edr_installed === 'No' && (
            <span className="text-warning"> · no EDR</span>
          )}
          <span className="text-muted"> · criticality {asset.criticality?.toLowerCase()}</span>
        </dd>

        <dt className="kv-label">vulnerability</dt>
        <dd className="text-ink">
          <span className="font-mono">{vulnerability.cve}</span>
          {vulnerability.cvss != null && (
            <span className="text-muted"> · CVSS {vulnerability.cvss}</span>
          )}
          <span className="text-muted"> · </span>
          {vulnerability.vulnerability_name}
        </dd>

        {threat_intel && (
          <>
            <dt className="kv-label">threat intel</dt>
            <dd className="text-ink">
              {threat_intel.threat_actor} / {threat_intel.campaign_name}
              <span className="text-muted"> · {threat_intel.exploit_maturity}</span>
              {threat_intel.ransomware_association === 'Yes' && (
                <span className="text-critical"> · ransomware-linked</span>
              )}
            </dd>
          </>
        )}

        <dt className="kv-label">service</dt>
        <dd className="text-ink">
          {business_service.name}
          {business_service.compliance_scope && (
            <span className="text-muted"> · {business_service.compliance_scope}</span>
          )}
          {business_service.revenue_impact && (
            <span className="text-muted"> · {business_service.revenue_impact.toLowerCase()} revenue impact</span>
          )}
        </dd>
      </dl>

      {why_sentence && (
        <p className="mt-6 text-sm leading-relaxed text-ink">{why_sentence}</p>
      )}

      <ControlBlock control={nist_control} />
    </article>
  )
}
