function formatTimestamp(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}

export default function Header({ generatedAt, dataQuality }) {
  return (
    <header className="border-b border-line pb-8">
      <p className="font-mono text-xs uppercase tracking-wider text-muted">
        Cyber Risk Assistant
      </p>
      <h1 className="mt-3 text-2xl font-semibold leading-tight">
        TawasolPay — top 5 ranked cyber risks
      </h1>
      <p className="mt-2 text-sm text-muted">
        Multi-factor scoring across asset exposure, active exploitation, ransomware linkage,
        business criticality, and missing compensating controls.
      </p>
      <div className="mt-5 flex flex-wrap gap-x-6 gap-y-1 font-mono text-xs text-muted">
        <span>generated {formatTimestamp(generatedAt)}</span>
        {dataQuality && (
          <>
            <span>
              threat intel matched {dataQuality.threat_intel_matched}/
              {dataQuality.threat_intel_total}
            </span>
            <span>kev hits {dataQuality.vulnerabilities_with_kev_hit}</span>
          </>
        )}
      </div>
    </header>
  )
}
