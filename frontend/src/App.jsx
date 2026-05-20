import { useEffect, useState } from 'react'
import Header from './components/Header'
import RiskEntry from './components/RiskEntry'
import Footer from './components/Footer'

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

  return (
    <div className="min-h-screen bg-base text-ink">
      <div className="mx-auto max-w-content px-6 pt-12">
        {error && (
          <p className="font-mono text-sm text-critical">error: {error}</p>
        )}
        {!data && !error && (
          <p className="font-mono text-sm text-muted">Loading…</p>
        )}
        {data && (
          <>
            <Header generatedAt={data.generated_at} dataQuality={data.data_quality} />
            <div>
              {data.risks.map((r) => (
                <RiskEntry key={r.rank} risk={r} />
              ))}
            </div>
            <Footer />
          </>
        )}
      </div>
    </div>
  )
}
