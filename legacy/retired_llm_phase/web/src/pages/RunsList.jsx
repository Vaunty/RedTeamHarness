import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { api } from '../api.js'
import { formatModelName } from '../utils.js'

/* ── Stagger animation for the card list ─────────────────────────── */
const containerVariants = {
  animate: {
    transition: { staggerChildren: 0.06 },
  },
}

const cardVariants = {
  initial: { opacity: 0, y: 16, filter: 'blur(4px)' },
  animate: {
    opacity: 1,
    y: 0,
    filter: 'blur(0px)',
    transition: { duration: 0.4, ease: [0.16, 1, 0.3, 1] },
  },
}

function formatDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export default function RunsList() {
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.getRuns()
      .then(setRuns)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="loading">Loading runs</div>
  if (error) return <div className="loading text-danger">{error}</div>

  if (runs.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⬡</div>
        <div className="empty-state-title">No runs yet</div>
        <div className="empty-state-desc">
          Run the harness with <code className="mono">python runner.py llama3.2:3b</code> to generate your first dataset.
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="page-header">
        <h1>
          Harness Runs
          <span className="tooltip-trigger" data-tooltip="A run represents a full suite of attack probes fired against one or more target models.">?</span>
        </h1>
        <p>All red-team sessions against your target models.</p>
      </div>

      <motion.div
        className="card-grid"
        variants={containerVariants}
        initial="initial"
        animate="animate"
      >
        {runs.map(run => {
          // Improve readability of defense_mode
          const defenseLabel = run.defense_mode === 'baseline' ? 'NO DEFENSES' : 'DEFENSES ACTIVE'
          const isMultiModel = Array.isArray(run.target_models) && run.target_models.length > 1
          
          return (
          <motion.div
            key={run.run_id}
            className="card run-card"
            variants={cardVariants}
            onClick={() => navigate(`/runs/${run.run_id}`)}
            whileHover={{ scale: 1.01, transition: { duration: 0.2 } }}
            whileTap={{ scale: 0.99 }}
          >
            <div className="run-card-header">
              <div>
                <div className="run-card-model">
                  {formatModelName(run.target_models)}
                  {isMultiModel && (
                    <span className="tooltip-trigger" data-tooltip="Running multiple models simultaneously helps you benchmark which LLM naturally resists attacks better under the exact same conditions.">i</span>
                  )}
                </div>
                <div className="run-card-id">{run.run_id.slice(0, 8)}</div>
              </div>
              <span 
                className={`badge ${run.defense_mode} has-tooltip`} 
                data-tooltip={run.defense_mode === 'baseline' ? "Raw models with no security layer applied." : "Models protected by the core/defenses.py logic."}
              >
                {defenseLabel}
              </span>
            </div>

            <div className="run-card-meta">
              <span className="mono has-tooltip" data-tooltip="The timestamp when this run was initiated" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                {formatDate(run.started_at)}
              </span>
              {run.probe_count && (
                <span className="mono has-tooltip" data-tooltip="Total number of adversarial probes fired during this run" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {run.probe_count} probes
                </span>
              )}
            </div>
          </motion.div>
          )
        })}
      </motion.div>
    </>
  )
}
