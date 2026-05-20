function severityClass(score) {
  if (score >= 80) return 'text-critical'
  if (score >= 50) return 'text-warning'
  return 'text-ink'
}

export default function ScoreBadge({ score }) {
  return (
    <div className="text-right">
      <div className={`font-mono text-4xl font-medium leading-none ${severityClass(score)}`}>
        {Math.round(score)}
      </div>
      <div className="mt-2 font-mono text-[10px] uppercase tracking-wider text-muted">
        risk score
      </div>
    </div>
  )
}
