import { Routes, Route, NavLink, useLocation } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import RunsList from './pages/RunsList.jsx'
import RunDetail from './pages/RunDetail.jsx'
import MetricsView from './pages/MetricsView.jsx'
import CompareView from './pages/CompareView.jsx'
import CRTBackground from './components/CRTBackground.jsx'

/* ── Glitch transition variants ──────────────────────────────────── */
const pageVariants = {
  initial: {
    opacity: 0,
    filter: 'blur(20px) hue-rotate(90deg) brightness(3)',
    x: -20,
    y: 10,
    scale: 1.05,
    skewX: 15,
  },
  animate: {
    opacity: [0, 1, 0.5, 1],
    filter: [
      'blur(20px) hue-rotate(90deg) brightness(3)',
      'blur(5px) hue-rotate(-45deg) brightness(1.5)',
      'blur(10px) hue-rotate(45deg) brightness(2)',
      'blur(0px) hue-rotate(0deg) brightness(1)'
    ],
    x: [-20, 15, -5, 0],
    y: [10, -10, 5, 0],
    scale: [1.05, 0.98, 1.02, 1],
    skewX: [15, -10, 5, 0],
    transition: {
      duration: 0.6,
      times: [0, 0.3, 0.6, 1],
      ease: 'easeOut',
    },
  },
  exit: {
    opacity: 0,
    filter: 'blur(10px) hue-rotate(-90deg) brightness(2)',
    x: 20,
    y: -10,
    scale: 0.95,
    skewX: -15,
    transition: {
      duration: 0.3,
      ease: 'easeIn',
    },
  },
}

function PageWrapper({ children }) {
  return (
    <motion.div
      variants={pageVariants}
      initial="initial"
      animate="animate"
      exit="exit"
    >
      {children}
    </motion.div>
  )
}

/* ── Sidebar ─────────────────────────────────────────────────────── */
function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        RED-TEAM HARNESS
      </div>

      <nav className="sidebar-nav">
        <NavLink to="/" end className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
          <span>⬡</span> Runs
        </NavLink>
        <NavLink to="/metrics" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
          <span>◈</span> Metrics
        </NavLink>
        <NavLink to="/compare" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
          <span>⇌</span> Compare
        </NavLink>
      </nav>

      <div style={{ marginTop: 'auto', paddingTop: 'var(--space-4)', borderTop: '1px solid var(--border-subtle)' }}>
        <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', lineHeight: 1.8 }}>
          <div>v2.0.0</div>
          <div style={{ color: 'var(--accent)', opacity: 0.6 }}>● system online</div>
        </div>
      </div>
    </aside>
  )
}

/* ── App Shell ───────────────────────────────────────────────────── */
export default function App() {
  const location = useLocation()

  return (
    <>
      <CRTBackground />
      <div className="app-shell glass-panel">
        <Sidebar />
        <main className="main-content">
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/" element={<PageWrapper><RunsList /></PageWrapper>} />
              <Route path="/runs/:runId" element={<PageWrapper><RunDetail /></PageWrapper>} />
              <Route path="/metrics" element={<PageWrapper><MetricsView /></PageWrapper>} />
              <Route path="/compare" element={<PageWrapper><CompareView /></PageWrapper>} />
            </Routes>
          </AnimatePresence>
        </main>
      </div>
    </>
  )
}
