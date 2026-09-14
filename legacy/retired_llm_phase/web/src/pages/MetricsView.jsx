import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import { api } from '../api.js'
import { formatModelName } from '../utils.js'
import { Maximize2, Minimize2 } from 'lucide-react'
import TagLegend from '../components/TagLegend.jsx'

const groupCategory = (cat) => {
  if (!cat) return 'Other'
  const lower = cat.toLowerCase()
  if (lower.startsWith('data_leak') || lower.startsWith('leak')) return 'Data Leak'
  if (lower.startsWith('visual_injection') || lower.startsWith('injection')) return 'Visual Injection'
  if (lower.startsWith('benign_control') || lower.startsWith('benign')) return 'Benign Control'
  return cat.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
}

export default function MetricsView() {
  const [runs, setRuns] = useState([])
  const [selectedRun, setSelectedRun] = useState(null)
  const [metrics, setMetrics] = useState(null)
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(true)
  const [expandedChart, setExpandedChart] = useState(null)

  const toggleExpand = (chartId) => {
    setExpandedChart(prev => prev === chartId ? null : chartId)
  }

  // Load runs on mount
  useEffect(() => {
    api.getRuns().then(r => {
      setRuns(r)
      if (r.length > 0) setSelectedRun(r[0].run_id)
    }).finally(() => setLoading(false))
  }, [])

  // Load metrics & raw results when selected run changes
  useEffect(() => {
    if (!selectedRun) return
    setMetrics(null)
    setResults([])
    Promise.all([
      api.getMetrics(selectedRun),
      api.getResults(selectedRun)
    ]).then(([m, res]) => {
      setMetrics(m)
      setResults(res)
    }).catch(() => {
      setMetrics(null)
      setResults([])
    })
  }, [selectedRun])

  if (loading) return <div className="loading">Loading metrics</div>

  if (runs.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">◈</div>
        <div className="empty-state-title">No metrics available</div>
        <div className="empty-state-desc">Run the harness to generate metrics data.</div>
      </div>
    )
  }

  // OWASP Breakdown Data
  const owaspData = metrics?.breakdowns?.asr_by_owasp
    ? Object.keys(metrics.breakdowns.asr_by_owasp).map(cat => {
        const asrVal = metrics.breakdowns.asr_by_owasp[cat] || 0
        const displayLabel = cat === 'clean' ? 'Benign' : cat
        return {
          name: displayLabel,
          asr: asrVal,
          refusal: 1 - asrVal
        }
      })
    : []

  // MITRE ATLAS Tactic Breakdown
  const mitreData = metrics?.breakdowns?.asr_by_mitre
    ? Object.entries(metrics.breakdowns.asr_by_mitre).map(([name, value]) => ({ name, value }))
    : []

  // Verdict composition by category (replacing the pie/donut chart)
  const catVerdicts = {}
  results.forEach(r => {
    const parentCat = groupCategory(r.category || r.attack_id)
    if (!catVerdicts[parentCat]) {
      catVerdicts[parentCat] = { name: parentCat, complied: 0, refused: 0, partial: 0 }
    }
    if (r.verdict === 'complied') catVerdicts[parentCat].complied++
    else if (r.verdict === 'refused') catVerdicts[parentCat].refused++
    else catVerdicts[parentCat].partial++
  })
  const stackedData = Object.values(catVerdicts)

  const overallASR = metrics?.overall?.overall_asr ?? 0
  const refusalRate = metrics?.overall?.refusal_rate ?? 0
  const judgeCalibration = metrics?.overall?.judge_calibration

  return (
    <>
      <div className="page-header">
        <h1>Metrics</h1>
        <p>Attack success rates and compliance breakdowns.</p>
      </div>

      {/* ── Run Selector ───────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 'var(--space-6)' }}>
        <div style={{ width: '100%', maxWidth: '500px' }}>
          <label className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: 'var(--space-2)' }}>
            SELECT RUN
          </label>
          <select
            value={selectedRun || ''}
            onChange={e => setSelectedRun(e.target.value)}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-primary)',
              padding: '8px 12px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              width: '100%',
              cursor: 'pointer',
            }}
          >
            {runs.map(r => (
              <option key={r.run_id} value={r.run_id}>
                {r.run_id.slice(0, 8)} — {formatModelName(r.target_models)} [{r.defense_mode === 'baseline' ? 'NO DEFENSES' : 'DEFENSES ACTIVE'}]
              </option>
            ))}
          </select>
        </div>
        
        {/* Minimal Dropdown Legend */}
        {metrics && <TagLegend minimal={true} />}
      </div>

      {!metrics ? (
        <div className="loading">Loading metrics for this run</div>
      ) : (
        <>
          {/* ── Overall Stats ────────────────────────────────────── */}
          <div className="stats-row">
            <motion.div
              className="stat-card"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <div className="stat-label">
                Overall ASR
                <span className="tooltip-trigger" data-tooltip="Attack Success Rate (ASR) is the percentage of malicious probes that bypassed the model's safety guardrails. Lower is better.">?</span>
              </div>
              <div className={`stat-value ${overallASR > 0.3 ? 'danger' : overallASR > 0.1 ? 'warning' : 'safe'}`}>
                {(overallASR * 100).toFixed(1)}%
              </div>
              <div className="stat-sub">Attack Success Rate</div>
            </motion.div>

            <motion.div
              className="stat-card"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <div className="stat-label">
                Refusal Rate
                <span className="tooltip-trigger" data-tooltip="The percentage of malicious requests where the model explicitly refused to comply with the attacker's intent. Higher is better.">?</span>
              </div>
              <div className="stat-value safe">
                {(refusalRate * 100).toFixed(1)}%
              </div>
              <div className="stat-sub">Attacks Blocked</div>
            </motion.div>

            {judgeCalibration !== undefined && judgeCalibration !== null && (
              <motion.div
                className="stat-card"
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <div className="stat-label">
                  Judge Calibration
                  <span className="tooltip-trigger" data-tooltip="Measures how often the automated LLM judge's verdict agreed with a human's ground-truth expectation during evaluation runs.">?</span>
                </div>
                <div className={`stat-value ${judgeCalibration > 0.9 ? 'safe' : 'warning'}`}>
                  {(judgeCalibration * 100).toFixed(1)}%
                </div>
                <div className="stat-sub">Agreement With Ground Truth</div>
              </motion.div>
            )}
          </div>

          {/* ── Charts ───────────────────────────────────────────── */}
          <div className="charts-grid">
            {/* ASR vs Refusal by OWASP */}
            {owaspData.length > 0 && (
              <motion.div
                className="chart-container"
                style={expandedChart === 'owasp' ? { gridColumn: '1 / -1' } : {}}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div className="chart-title" style={{ margin: 0 }}>ASR vs Block (Refusal) by OWASP Category</div>
                  <button className="icon-btn" onClick={() => toggleExpand('owasp')}>
                    {expandedChart === 'owasp' ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                  </button>
                </div>
                <ResponsiveContainer width="100%" height={expandedChart === 'owasp' ? 500 : 300} style={{ outline: 'none' }}>
                  <BarChart data={owaspData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis
                      dataKey="name"
                      tick={{ fill: '#8a8a9a', fontSize: 10, fontFamily: "'JetBrains Mono'" }}
                      tickLine={false}
                    />
                    <YAxis
                      tickFormatter={(value) => `${value * 100}%`}
                      tick={{ fill: '#8a8a9a', fontSize: 10, fontFamily: "'JetBrains Mono'" }}
                      tickLine={false}
                      domain={[0, 1]}
                    />
                    <Tooltip content={({ active, payload, label }) => {
                      if (!active || !payload?.length) return null
                      return (
                        <div style={{
                          background: '#16161f',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                          padding: '10px 14px',
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.75rem',
                        }}>
                          <div style={{ color: '#8a8a9a', marginBottom: 6 }}>{label}</div>
                          <div style={{ color: 'var(--danger)', fontWeight: 600 }}>
                            ASR: {(payload[0].value * 100).toFixed(1)}%
                          </div>
                          <div style={{ color: 'var(--safe)', fontWeight: 600, marginTop: 2 }}>
                            Refused: {(payload[1].value * 100).toFixed(1)}%
                          </div>
                        </div>
                      )
                    }} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                    <Legend wrapperStyle={{ fontSize: 10, fontFamily: "'JetBrains Mono'" }} />
                    <Bar dataKey="asr" name="ASR (Vulnerability)" fill="var(--danger)" isAnimationActive={false} radius={[4, 4, 0, 0]} />
                    <Bar dataKey="refusal" name="Blocked (Refusal)" fill="var(--safe)" isAnimationActive={false} radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </motion.div>
            )}

            {/* Stacked Verdicts by Parent Category */}
            {stackedData.length > 0 && (
              <motion.div
                className="chart-container"
                style={expandedChart === 'verdict' ? { gridColumn: '1 / -1' } : {}}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div className="chart-title" style={{ margin: 0 }}>Attack Verdicts by Category</div>
                  <button className="icon-btn" onClick={() => toggleExpand('verdict')}>
                    {expandedChart === 'verdict' ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                  </button>
                </div>
                <ResponsiveContainer width="100%" height={expandedChart === 'verdict' ? 500 : 300} style={{ outline: 'none' }}>
                  <BarChart data={stackedData} layout="vertical" margin={{ top: 20, right: 30, left: 10, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis type="number" tick={{ fill: '#8a8a9a', fontSize: 10, fontFamily: "'JetBrains Mono'" }} />
                    <YAxis dataKey="name" type="category" tick={{ fill: '#8a8a9a', fontSize: 10, fontFamily: "'JetBrains Mono'" }} width={100} />
                    <Tooltip content={({ active, payload, label }) => {
                      if (!active || !payload?.length) return null
                      return (
                        <div style={{
                          background: '#16161f',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                          padding: '10px 14px',
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.75rem',
                        }}>
                          <div style={{ color: '#8a8a9a', marginBottom: 6, fontWeight: 600 }}>{label}</div>
                          <div style={{ color: 'var(--safe)' }}>Blocked (Refused): {payload[0].value}</div>
                          <div style={{ color: 'var(--warning)', marginTop: 2 }}>Partial: {payload[1].value}</div>
                          <div style={{ color: 'var(--danger)', marginTop: 2 }}>Leaked (Complied): {payload[2].value}</div>
                        </div>
                      )
                    }} />
                    <Legend wrapperStyle={{ fontSize: 10, fontFamily: "'JetBrains Mono'" }} />
                    <Bar dataKey="refused" name="Blocked (Refused)" stackId="a" fill="var(--safe)" />
                    <Bar dataKey="partial" name="Partial" stackId="a" fill="var(--warning)" />
                    <Bar dataKey="complied" name="Leaked (Complied)" stackId="a" fill="var(--danger)" />
                  </BarChart>
                </ResponsiveContainer>
              </motion.div>
            )}

            {/* MITRE Heatmap Grid */}
            {mitreData.length > 0 && (
              <motion.div
                className="chart-container"
                style={{ gridColumn: '1 / -1' }}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
              >
                <div className="chart-title">MITRE ATLAS Framework Coverage</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '12px', marginTop: '16px' }}>
                  {mitreData.map(m => {
                    const label = m.name === 'clean' ? 'Benign Controls' : m.name
                    return (
                      <div key={m.name} style={{
                        background: m.value > 0.5 ? 'rgba(255,0,170,0.1)' : m.value > 0 ? 'rgba(255,221,0,0.1)' : 'rgba(0,255,136,0.1)',
                        border: `1px solid ${m.value > 0.5 ? 'var(--danger)' : m.value > 0 ? 'var(--warning)' : 'var(--safe)'}`,
                        padding: '16px 12px', borderRadius: '6px', textAlign: 'center'
                      }}>
                        <div className="mono" style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{label}</div>
                        <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#fff', marginTop: '6px' }}>{(m.value * 100).toFixed(1)}%</div>
                        <div style={{ fontSize: '0.6rem', color: 'rgba(255,255,255,0.4)', marginTop: '2px', textTransform: 'uppercase' }}>ASR</div>
                      </div>
                    )
                  })}
                </div>
              </motion.div>
            )}
          </div>
        </>
      )}
    </>
  )
}
