import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { api } from '../api.js'
import { formatModelName } from '../utils.js'

export default function CompareView() {
  const [runs, setRuns] = useState([])
  const [baselineId, setBaselineId] = useState('')
  const [defendedId, setDefendedId] = useState('')
  const [comparison, setComparison] = useState(null)
  const [loading, setLoading] = useState(true)
  const [comparing, setComparing] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.getRuns().then(r => {
      setRuns(r)
      // Auto-select baseline and defended if both exist
      const baselines = r.filter(x => x.defense_mode === 'baseline')
      const defended  = r.filter(x => x.defense_mode !== 'baseline')
      if (baselines.length > 0) setBaselineId(baselines[0].run_id)
      if (defended.length > 0)  setDefendedId(defended[0].run_id)
    }).finally(() => setLoading(false))
  }, [])

  const handleCompare = () => {
    if (!baselineId || !defendedId) return
    setComparing(true)
    setError(null)
    api.compareRuns(baselineId, defendedId)
      .then(setComparison)
      .catch(e => setError(e.message))
      .finally(() => setComparing(false))
  }

  if (loading) return <div className="loading">Loading runs</div>

  if (runs.length < 2) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⇌</div>
        <div className="empty-state-title">Need at least two runs to compare</div>
        <div className="empty-state-desc">
          Run the harness once in baseline mode and once with <code className="mono">--defense</code> to see the delta.
        </div>
      </div>
    )
  }

  const selectStyle = {
    background: 'var(--bg-card)',
    border: '1px solid var(--border-default)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    padding: '8px 12px',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8rem',
    width: '100%',
    cursor: 'pointer',
  }

  return (
    <>
      <div className="page-header">
        <h1>
          Compare Runs
          <span className="tooltip-trigger tooltip-right" data-tooltip="Measure the direct impact of your security logic. Compare an unprotected run (raw model) against a protected run (same model, but with defenses.py active) to see the ASR drop.">?</span>
        </h1>
        <p>Measure the impact of your defense layer by comparing a run with no defenses against one with defenses active.</p>
      </div>

      {/* ── Selectors ──────────────────────────────────────────── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr auto',
        gap: 'var(--space-4)',
        alignItems: 'end',
        marginBottom: 'var(--space-6)',
      }}>
        <div>
          <label className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: 'var(--space-2)' }}>
            NO DEFENSES
            <span className="tooltip-trigger tooltip-right" data-tooltip="Shows how vulnerable the naked model is. Only runs where no security layer was applied are listed here.">?</span>
          </label>
          <select value={baselineId} onChange={e => setBaselineId(e.target.value)} style={selectStyle}>
            <option value="">Select unprotected run...</option>
            {runs.filter(r => r.defense_mode === 'baseline').map(r => (
              <option key={r.run_id} value={r.run_id}>
                {r.run_id.slice(0, 8)} — {formatModelName(r.target_models)}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: 'var(--space-2)' }}>
            DEFENSES ACTIVE
            <span className="tooltip-trigger tooltip-left" data-tooltip="Shows the model after passing through your security layer. Only runs where defenses were active are listed here.">?</span>
          </label>
          <select value={defendedId} onChange={e => setDefendedId(e.target.value)} style={selectStyle}>
            <option value="">Select protected run...</option>
            {runs.filter(r => r.defense_mode !== 'baseline').map(r => (
              <option key={r.run_id} value={r.run_id}>
                {r.run_id.slice(0, 8)} — {formatModelName(r.target_models)}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={handleCompare}
          disabled={!baselineId || !defendedId || comparing}
          style={{
            background: 'var(--accent-glow)',
            border: '1px solid rgba(0,255,136,0.2)',
            borderRadius: 'var(--radius-sm)',
            color: 'var(--accent)',
            padding: '8px 20px',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.8rem',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.2s',
            opacity: (!baselineId || !defendedId || comparing) ? 0.4 : 1,
          }}
        >
          {comparing ? 'Analyzing...' : 'Compare'}
        </button>
      </div>

      {error && <div style={{ color: 'var(--danger)', marginBottom: 'var(--space-4)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{error}</div>}

      {/* ── Comparison Results ─────────────────────────────────── */}
      {comparison && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <div className="stats-row">
            <motion.div
              className="stat-card"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1 }}
            >
              <div className="stat-label">
                BASELINE ASR <span className="tooltip-trigger tooltip-down" data-tooltip="Attack Success Rate when no defenses were active.">?</span>
              </div>
              <div className="stat-value danger">{(comparison.baseline * 100).toFixed(1)}%</div>
              <div className="stat-sub">Before Defenses</div>
            </motion.div>

            <motion.div
              className="stat-card"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2 }}
            >
              <div className="stat-label">
                DEFENDED ASR <span className="tooltip-trigger tooltip-down" data-tooltip="Attack Success Rate with defenses active.">?</span>
              </div>
              <div className="stat-value safe">{(comparison.defended * 100).toFixed(1)}%</div>
              <div className="stat-sub">After Defenses</div>
            </motion.div>

            <motion.div
              className="stat-card"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.3 }}
            >
              <div className="stat-label">Reduction</div>
              <div className="stat-value" style={{ color: 'var(--accent)' }}>
                {comparison.reduction_pct?.toFixed(1)}%
              </div>
              <div className="stat-sub">fewer successful attacks</div>
            </motion.div>
          </div>

          {/* ── Visual Comparison Bars ────────────────────────── */}
          <div className="card mt-6">
            <div className="chart-title">ASR Comparison</div>

            <div className="compare-bar">
              <div className="compare-label">Baseline</div>
              <div className="compare-track">
                <motion.div
                  className="compare-fill baseline"
                  initial={{ width: 0 }}
                  animate={{ width: `${comparison.baseline * 100}%` }}
                  transition={{ delay: 0.5, duration: 1, ease: [0.16, 1, 0.3, 1] }}
                />
              </div>
              <div className="compare-value text-danger">
                {(comparison.baseline * 100).toFixed(1)}%
              </div>
            </div>

            <div className="compare-bar">
              <div className="compare-label">Defended</div>
              <div className="compare-track">
                <motion.div
                  className="compare-fill defended"
                  initial={{ width: 0 }}
                  animate={{ width: `${comparison.defended * 100}%` }}
                  transition={{ delay: 0.7, duration: 1, ease: [0.16, 1, 0.3, 1] }}
                />
              </div>
              <div className="compare-value text-accent">
                {(comparison.defended * 100).toFixed(1)}%
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </>
  )
}
