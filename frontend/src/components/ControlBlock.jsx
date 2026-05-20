export default function ControlBlock({ control }) {
  return (
    <div className="mt-6 border-l border-line bg-surface px-5 py-4">
      <div className="font-mono text-xs uppercase tracking-wider text-muted">
        NIST SP 800-53 control
      </div>
      <div className="mt-2 flex flex-wrap items-baseline gap-x-3">
        <span className="font-mono text-base font-medium text-ink">
          {control.control_id}
        </span>
        <span className="text-sm text-ink">{control.title}</span>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-muted">{control.summary}</p>
    </div>
  )
}
