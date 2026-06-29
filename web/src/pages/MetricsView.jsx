import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  ScatterChart, Scatter, ZAxis
} from 'recharts'
import { api } from '../api.js'
import { formatModelName } from '../utils.js'
import { Maximize2, Minimize2 } from 'lucide-react'
import TagLegend from '../components/TagLegend.jsx'

/* ── Chart color palette ─────────────────────────────────────────── */
const COLORS = ['#ff4466', '#ff9933', '#00ff88', '#8888ff', '#ff66cc', '#66ccff', '#ffcc33']

/* ── Custom tooltip styling ──────────────────────────────────────── */
const CustomTooltip = ({ active, payload, label }) => {
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
      <div style={{ color: '#8a8a9a', marginBottom: 4 }}>{label}</div>
      <div style={{ color: '#e8e8ed', fontWeight: 600 }}>
        ASR: {(payload[0].value * 100).toFixed(1)}%
      </div>
    </div>
  )
}

export default function MetricsView() {
  const [runs, setRuns] = useState([])
  const [selectedRun, setSelectedRun] = useState(null)
  const [metrics, setMetrics] = useState(null)
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

  // Load metrics when selected run changes
  useEffect(() => {
    if (!selectedRun) return
    setMetrics(null)
    api.getMetrics(selectedRun)
      .then(setMetrics)
      .catch(() => setMetrics(null))
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

  const owaspData = metrics?.breakdowns?.asr_by_owasp
    ? Object.keys(metrics.breakdowns.asr_by_owasp).map(cat => {
        const asrVal = metrics.breakdowns.asr_by_owasp[cat] || 0;
        // Search if we have refusal rate by OWASP; fallback to computing it roughly or displaying as (1 - asr)
        return {
          name: cat,
          asr: asrVal,
          refusal: 1 - asrVal
        };
      })
    : []

  const categoryData = metrics?.breakdowns?.asr_by_category
    ? Object.entries(metrics.breakdowns.asr_by_category).map(([name, value]) => ({ name, value }))
    : []

  const mitreData = metrics?.breakdowns?.asr_by_mitre
    ? Object.entries(metrics.breakdowns.asr_by_mitre).map(([name, value]) => ({ name, value }))
    : []

  const scatterData = []
  if (metrics?.breakdowns?.scatter_asr && metrics?.breakdowns?.scatter_count) {
    Object.keys(metrics.breakdowns.scatter_asr).forEach(cat => {
      Object.keys(metrics.breakdowns.scatter_asr[cat]).forEach(sev => {
        scatterData.push({
          category: cat.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
          severity: parseInt(sev),
          asr: metrics.breakdowns.scatter_asr[cat][sev],
          count: metrics.breakdowns.scatter_count[cat][sev]
        })
      })
    })
  }

  const categories = Array.from(new Set(scatterData.map(d => d.category)))
  const dataWithIndex = scatterData.map(d => ({
    ...d,
    catIndex: categories.indexOf(d.category)
  }))

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
            {/* ASR by OWASP */}
            {owaspData.length > 0 && (
              <motion.div
                className="chart-container"
                style={expandedChart === 'owasp' ? { gridColumn: '1 / -1' } : {}}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div className="chart-title" style={{ margin: 0 }}>Attack Success (ASR) vs Block (Refusal) by OWASP Category</div>
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

            {/* ASR by Category (Pie) */}
            {categoryData.length > 0 && (
              <motion.div
                className="chart-container"
                style={expandedChart === 'category' ? { gridColumn: '1 / -1' } : {}}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div className="chart-title" style={{ margin: 0 }}>ASR by Attack Category</div>
                  <button className="icon-btn" onClick={() => toggleExpand('category')}>
                    {expandedChart === 'category' ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                  </button>
                </div>
                <ResponsiveContainer width="100%" height={expandedChart === 'category' ? 500 : 300} style={{ outline: 'none' }}>
                  <PieChart>
                    <Pie
                      data={categoryData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                      isAnimationActive={false}
                    >
                      {categoryData.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} fillOpacity={0.85} />
                      ))}
                    </Pie>
                    <Legend
                      formatter={(value) => (
                        <span style={{ color: '#8a8a9a', fontFamily: "'JetBrains Mono'", fontSize: '0.7rem' }}>
                          {value.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                        </span>
                      )}
                    />
                    <Tooltip
                      formatter={(value) => `${(value * 100).toFixed(1)}%`}
                      contentStyle={{
                        background: '#16161f',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                        fontFamily: "'JetBrains Mono'",
                        fontSize: '0.75rem',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </motion.div>
            )}
            
            {/* Severity Scatter Plot */}
            {scatterData.length > 0 && (
              <motion.div
                className="chart-container"
                style={expandedChart === 'scatter' ? { gridColumn: '1 / -1' } : {}}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div className="chart-title" style={{ margin: 0 }}>Attack Severity vs Vulnerability Map</div>
                  <button className="icon-btn" onClick={() => toggleExpand('scatter')}>
                    {expandedChart === 'scatter' ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                  </button>
                </div>
                <div style={{ width: '100%', overflowX: 'auto', overflowY: 'hidden', outline: 'none' }}>
                  <div style={{ minWidth: `${Math.max(100, categories.length * 80)}px`, height: expandedChart === 'scatter' ? 500 : 300 }}>
                    <ResponsiveContainer width="100%" height="100%" style={{ outline: 'none' }}>
                      <ScatterChart margin={{ top: 20, right: 30, bottom: 70, left: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                        <XAxis 
                          type="number" 
                          dataKey="catIndex" 
                          name="Category" 
                          domain={[-0.5, categories.length - 0.5]} 
                          ticks={categories.map((_, i) => i)}
                          tickFormatter={(i) => categories[i]}
                          tick={{ fill: '#8a8a9a', fontSize: 10, fontFamily: "'JetBrains Mono'", angle: -45, textAnchor: 'end', dy: 15 }} 
                        />
                    <YAxis type="number" dataKey="severity" name="Severity" domain={[0, 6]} ticks={[1,2,3,4,5]} tick={{ fill: '#8a8a9a', fontSize: 11, fontFamily: "'JetBrains Mono'" }} label={{ value: 'Sev (1-5)', angle: -90, position: 'insideLeft', fill: '#8a8a9a', fontSize: 10 }} />
                    <ZAxis type="number" dataKey="count" range={[40, 400]} name="Volume" />
                    <Tooltip cursor={{ strokeDasharray: '3 3' }} content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const d = payload[0].payload;
                      return (
                        <div style={{ background: '#16161f', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', padding: '10px 14px', fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem' }}>
                          <div style={{ color: '#fff', fontWeight: 600, marginBottom: 4 }}>{d.category} (Sev {d.severity})</div>
                          <div style={{ color: '#8a8a9a' }}>Probes: {d.count}</div>
                          <div style={{ color: d.asr > 0.5 ? 'var(--danger)' : d.asr > 0 ? 'var(--warning)' : 'var(--safe)' }}>ASR: {(d.asr * 100).toFixed(1)}%</div>
                        </div>
                      );
                    }} />
                    <Scatter data={dataWithIndex} isAnimationActive={false} style={{ outline: 'none' }}>
                      {dataWithIndex.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.asr > 0.5 ? 'var(--danger)' : entry.asr > 0 ? 'var(--warning)' : 'var(--safe)'} fillOpacity={0.8} style={{ outline: 'none' }} />
                      ))}
                    </Scatter>
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            </div>
              </motion.div>
            )}

            {/* MITRE Heatmap Grid */}
            {mitreData.length > 0 && (
              <motion.div
                className="chart-container"
                style={expandedChart === 'mitre' ? { gridColumn: '1 / -1' } : {}}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.6 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div className="chart-title" style={{ margin: 0 }}>MITRE ATLAS Framework Heatmap</div>
                  <button className="icon-btn" onClick={() => toggleExpand('mitre')}>
                    {expandedChart === 'mitre' ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                  </button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fill, minmax(${expandedChart === 'mitre' ? '180px' : '110px'}, 1fr))`, gap: '8px', marginTop: '16px' }}>
                  {mitreData.map(m => (
                    <div key={m.name} style={{
                      background: m.value > 0.5 ? 'rgba(255,0,170,0.15)' : m.value > 0 ? 'rgba(255,221,0,0.15)' : 'rgba(0,255,136,0.15)',
                      border: `1px solid ${m.value > 0.5 ? 'var(--danger)' : m.value > 0 ? 'var(--warning)' : 'var(--safe)'}`,
                      padding: '12px 8px', borderRadius: '4px', textAlign: 'center', transition: 'all 0.2s'
                    }}>
                      <div className="mono" style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>{m.name}</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#fff', marginTop: '6px' }}>{(m.value * 100).toFixed(1)}%</div>
                      <div style={{ fontSize: '0.6rem', color: 'rgba(255,255,255,0.4)', marginTop: '2px', textTransform: 'uppercase' }}>ASR</div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </div>
        </>
      )}
    </>
  )
}
