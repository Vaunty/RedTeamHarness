import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, Info } from 'lucide-react'

const OWASP_ENTRIES = [
  { id: 'LLM01', title: 'Prompt Injection', desc: 'Crafted inputs that bypass filters or hijack model instructions.' },
  { id: 'LLM02', title: 'Insecure Output Handling', desc: 'XSS, CSRF, or SSRF caused by blindly trusting model outputs.' },
  { id: 'LLM03', title: 'Training Data Poisoning', desc: 'Tampering with the model\'s training data or fine-tuning process.' },
  { id: 'LLM04', title: 'Model Denial of Service', desc: 'Resource exhaustion via heavy requests or recursive processing.' },
  { id: 'LLM05', title: 'Supply Chain Vulnerabilities', desc: 'Compromised dependencies, models, or datasets in the pipeline.' },
  { id: 'LLM06', title: 'Sensitive Information Disclosure', desc: 'Leaking PII, secrets, or proprietary data through model outputs.' },
  { id: 'LLM07', title: 'Insecure Plugin Design', desc: 'Exploiting poorly secured LLM extensions and external tools.' },
  { id: 'LLM08', title: 'Excessive Agency', desc: 'Granting the LLM overly broad permissions to take destructive actions.' },
  { id: 'LLM09', title: 'Overreliance', desc: 'Blindly trusting hallucinated or unsafe outputs without human oversight.' },
  { id: 'LLM10', title: 'Model Theft', desc: 'Unauthorized access, exfiltration, or copying of the model weights.' },
]

const MITRE_ENTRIES = [
  { id: 'AML.T0054', title: 'Jailbreak', desc: 'Crafting inputs to bypass safety filters and constraints.' },
  { id: 'AML.T0043', title: 'Craft Adversarial Data', desc: 'Generating inputs designed to cause misclassification or errors.' },
  { id: 'AML.T0040', title: 'Data Poisoning', desc: 'Injecting malicious data into the training or fine-tuning set.' },
  { id: 'AML.T0024', title: 'Exfiltration', desc: 'Extracting sensitive information from the model outputs.' },
  { id: 'AML.T0016', title: 'Obtain Capabilities', desc: 'Acquiring specific tools or methods to attack the system.' }
]

export default function TagLegend({ minimal = false }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div style={{
      background: minimal ? 'rgba(255,255,255,0.02)' : 'rgba(0, 240, 255, 0.03)',
      border: minimal ? '1px solid rgba(255,255,255,0.1)' : '1px solid rgba(0, 240, 255, 0.15)',
      borderRadius: 'var(--radius-sm)',
      padding: minimal ? '8px 12px' : '12px 16px',
      marginBottom: minimal ? '0' : 'var(--space-6)',
      display: 'flex',
      flexDirection: 'column',
      gap: minimal ? '0' : 'var(--space-4)',
      fontFamily: 'var(--font-mono)',
      fontSize: '0.75rem',
      color: 'var(--text-secondary)',
      position: minimal ? 'relative' : 'static',
      width: minimal ? 'max-content' : 'auto',
      userSelect: 'none'
    }}>
      <div 
        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', gap: minimal ? '16px' : '0' }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: minimal ? 'var(--text-primary)' : 'var(--accent)' }}>
          <Info size={16} color={minimal ? "var(--accent)" : "currentColor"} />
          <span style={{ fontWeight: 600 }}>TAG LEGEND</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: minimal ? 'var(--accent)' : 'var(--text-muted)', fontSize: '0.65rem' }}>
          {!minimal && (expanded ? 'CLICK TO COLLAPSE' : 'CLICK TO EXPAND CATALOG')}
          <motion.div animate={{ rotate: expanded ? 180 : 0 }} transition={{ duration: 0.3 }}>
            <ChevronDown size={14} />
          </motion.div>
        </div>
      </div>
      
      {!minimal && (
        <div style={{ display: 'grid', gap: '8px' }}>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
            <span className="badge owasp" style={{ minWidth: '60px', textAlign: 'center' }}>LLM0X</span>
            <span><strong>OWASP Top 10 for LLMs:</strong> The vulnerability class standard. {expanded ? '' : '(Expand to see all)'}</span>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
            <span className="badge mitre" style={{ minWidth: '60px', textAlign: 'center' }}>AML.TXXX</span>
            <span><strong>MITRE ATLAS:</strong> Defines the specific adversarial tactic used by the attacker (e.g., AML.T0054 - Jailbreak).</span>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
            <span className="badge" style={{ minWidth: '60px', textAlign: 'center', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)' }}>sev X</span>
            <span><strong>Severity (1-5):</strong> The impact level of the attack if successful, where 5 is critical.</span>
          </div>
        </div>
      )}

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={minimal ? { opacity: 0, y: -10 } : { opacity: 0, height: 0 }}
            animate={minimal ? { opacity: 1, y: 0 } : { opacity: 1, height: 'auto' }}
            exit={minimal ? { opacity: 0, y: -10 } : { opacity: 0, height: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            style={minimal ? {
              position: 'absolute',
              top: 'calc(100% + 8px)',
              right: 0,
              width: '380px',
              maxHeight: '60vh',
              overflowY: 'auto',
              background: 'rgba(15,15,20,0.85)',
              backdropFilter: 'blur(16px)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '8px',
              padding: '12px',
              zIndex: 999,
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              cursor: 'default'
            } : { overflow: 'hidden' }}
            onClick={(e) => e.stopPropagation()}
          >
            {minimal && (
              <div style={{ display: 'grid', gap: '8px', marginBottom: '12px', paddingBottom: '12px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '0.7rem' }}>
                  <span className="badge owasp" style={{ minWidth: '50px', textAlign: 'center', fontSize: '0.55rem' }}>LLM0X</span>
                  <span><strong>OWASP Top 10 for LLMs:</strong> The vulnerability class standard.</span>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '0.7rem' }}>
                  <span className="badge mitre" style={{ minWidth: '50px', textAlign: 'center', fontSize: '0.55rem' }}>AML.TXXX</span>
                  <span><strong>MITRE ATLAS:</strong> Defines the specific adversarial tactic used.</span>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '0.7rem' }}>
                  <span className="badge" style={{ minWidth: '50px', textAlign: 'center', fontSize: '0.55rem', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)' }}>sev X</span>
                  <span><strong>Severity (1-5):</strong> The impact level of the attack if successful.</span>
                </div>
              </div>
            )}
            <div style={minimal ? {} : { marginTop: '12px', paddingTop: '12px', borderTop: '1px solid rgba(0, 240, 255, 0.1)' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px', marginBottom: '16px' }}>
                {OWASP_ENTRIES.map(entry => (
                  <div key={entry.id} style={{ background: 'rgba(0,0,0,0.2)', padding: '8px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.03)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                      <span className="badge owasp" style={{ fontSize: '0.6rem', padding: '1px 4px' }}>{entry.id}</span>
                      <strong style={{ color: 'var(--text-primary)', fontSize: '0.7rem' }}>{entry.title}</strong>
                    </div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{entry.desc}</div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px' }}>
                {MITRE_ENTRIES.map(entry => (
                  <div key={entry.id} style={{ background: 'rgba(0,0,0,0.2)', padding: '8px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.03)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                      <span className="badge mitre" style={{ fontSize: '0.6rem', padding: '1px 4px' }}>{entry.id}</span>
                      <strong style={{ color: 'var(--text-primary)', fontSize: '0.7rem' }}>{entry.title}</strong>
                    </div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{entry.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
