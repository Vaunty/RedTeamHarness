import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../api.js'
import { ChevronDown, Info } from 'lucide-react'
import TagLegend from '../components/TagLegend.jsx'

/* ── Stagger animation ───────────────────────────────────────────── */
const listVariants = {
  animate: { transition: { staggerChildren: 0.04 } },
}

const itemVariants = {
  initial: { opacity: 0, x: -12 },
  animate: {
    opacity: 1,
    x: 0,
    transition: { duration: 0.35, ease: [0.16, 1, 0.3, 1] },
  },
}

/**
 * Parse the raw transcript string into structured segments.
 * Returns an array of { role: 'attacker'|'target', text: string }
 */
function parseTranscript(raw) {
  if (!raw) return []
  const segments = []
  const parts = raw.split(/\n\n/)
  for (const part of parts) {
    const trimmed = part.trim()
    if (!trimmed) continue
    if (trimmed.startsWith('ATTACKER:')) {
      segments.push({ role: 'attacker', text: trimmed.replace(/^ATTACKER:\s*/, '') })
    } else if (trimmed.startsWith('TARGET:')) {
      segments.push({ role: 'target', text: trimmed.replace(/^TARGET:\s*/, '') })
    } else {
      segments.push({ role: 'target', text: trimmed })
    }
  }
  return segments
}

function TranscriptViewer({ response }) {
  const segments = parseTranscript(response)
  if (segments.length === 0) {
    return <div className="transcript">{response || 'No response recorded.'}</div>
  }
  return (
    <div className="transcript">
      {segments.map((seg, i) => (
        <div key={i} style={{ marginBottom: '12px' }}>
          <span className={`label ${seg.role}`}>
            {seg.role === 'attacker' ? 'ATTACKER' : 'TARGET'}:
          </span>{' '}
          <span className={seg.role}>{seg.text}</span>
        </div>
      ))}
    </div>
  )
}

function formatModelName(name) {
  if (!name) return ''
  if (name.includes('llama3.2:3b')) return name.replace('llama3.2:3b', 'Llama 3.2: 3B')
  if (name.includes('qwen2.5:3b')) return name.replace('qwen2.5:3b', 'Qwen 2.5: 3B')
  return name.charAt(0).toUpperCase() + name.slice(1)
}

export default function RunDetail() {
  const { runId } = useParams()
  const navigate = useNavigate()
  const [run, setRun] = useState(null)
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    Promise.all([api.getRun(runId), api.getResults(runId)])
      .then(([r, res]) => { setRun(r); setResults(res) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [runId])

  if (loading) return <div className="loading">Loading run data</div>
  if (!run) return <div className="loading text-danger">Run not found</div>

  const compliedCount = results.filter(r => r.verdict === 'complied').length
  const refusedCount = results.filter(r => r.verdict === 'refused').length
  const asr = results.length > 0 ? ((compliedCount / results.length) * 100).toFixed(1) : '0.0'

  return (
    <>
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', marginBottom: 'var(--space-2)' }}>
          <button
            onClick={() => navigate('/runs')}
            style={{
              background: 'transparent', border: '1px solid var(--border-default)',
              color: 'var(--text-secondary)', borderRadius: 'var(--radius-sm)',
              padding: '4px 12px', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: '0.75rem'
            }}
          >
            ← Back
          </button>
          <span className={`badge ${run.defense_mode}`}>
            {run.defense_mode === 'baseline' ? 'NO DEFENSES' : 'DEFENSES ACTIVE'}
          </span>
        </div>
        <h1 style={{ fontSize: '2.5rem', marginBottom: 'var(--space-2)' }}>
          {Array.isArray(run.target_models) ? run.target_models.map(formatModelName).join(', ') : formatModelName(run.target_models)}
        </h1>
        <div className="mono" style={{ color: 'var(--text-muted)' }}>
          Run ID: {run.run_id.slice(0, 8)} • {run.probe_count} Probes
        </div>
      </div>

      {/* ── Stats Row ──────────────────────────────────────────── */}
      <div className="stats-row">
        <motion.div
          className="stat-card"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
        >
          <div className="stat-label">Attack Success Rate</div>
          <div className={`stat-value ${parseFloat(asr) > 30 ? 'danger' : parseFloat(asr) > 10 ? 'warning' : 'safe'}`}>
            {asr}%
          </div>
        </motion.div>

        <motion.div
          className="stat-card"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
        >
          <div className="stat-label">Complied</div>
          <div className="stat-value danger">{compliedCount}</div>
          <div className="stat-sub">Attacks Succeeded</div>
        </motion.div>

        <motion.div className="stat-card" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <div className="stat-label">REFUSED</div>
          <div className="stat-value safe">{refusedCount}</div>
          <div className="stat-sub">Attacks Blocked</div>
        </motion.div>
      </div>

      {/* ── Results List ───────────────────────────────────────── */}
      <TagLegend />
      
      <motion.div
        className="result-list"
        variants={listVariants}
        initial="initial"
        animate="animate"
      >
        {results.map((r, i) => (
          <motion.div
            key={i}
            className="result-item"
            variants={itemVariants}
            onClick={() => setExpanded(expanded === i ? null : i)}
            layout
          >
            <div className="result-item-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span className="mono" style={{ fontWeight: 600, fontSize: '0.85rem' }}>
                  {r.attack}
                </span>
                <span className={`badge ${r.verdict}`}>{r.verdict}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '0.7rem', fontFamily: 'var(--font-mono)' }}>
                <span style={{ opacity: expanded === i ? 0 : 0.6, transition: 'opacity 0.2s' }}>CLICK TO REVEAL</span>
                <motion.div
                  animate={{ rotate: expanded === i ? 180 : 0 }}
                  transition={{ duration: 0.3 }}
                >
                  <ChevronDown size={16} />
                </motion.div>
              </div>
            </div>

            <div className="result-item-technique">{r.technique}</div>

            <div className="result-item-tags">
              <span className="badge owasp">{r.owasp}</span>
              {r.mitre && <span className="badge mitre">{r.mitre}</span>}
              <span className="badge" style={{
                background: 'rgba(255,255,255,0.05)',
                color: 'var(--text-muted)',
                border: '1px solid var(--border-subtle)',
              }}>
                sev {r.severity}
              </span>
            </div>

            <AnimatePresence>
              {expanded === i && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                  style={{ overflow: 'hidden', marginTop: 'var(--space-4)' }}
                >
                  <TranscriptViewer response={r.response} />
                  {r.reason && (
                    <div style={{ marginTop: 'var(--space-3)', fontSize: '0.8rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                      Judge reasoning: {r.reason}
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        ))}
      </motion.div>
    </>
  )
}
