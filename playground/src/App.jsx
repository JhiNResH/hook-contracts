import React, { useState, useEffect } from 'react';
import PipelineSimulator from './components/PipelineSimulator.jsx';
import SynthesisReplay from './components/SynthesisReplay.jsx';
import CompareMode from './components/CompareMode.jsx';

const TABS = [
  { id: 'simulator', label: '🔬 Simulator', icon: '' },
  { id: 'synthesis', label: '🎮 Synthesis Replay', icon: '' },
  { id: 'compare', label: '⚖️ Compare', icon: '' },
];

function ThemeToggle({ dark, onToggle }) {
  return (
    <button
      onClick={onToggle}
      className="p-2 rounded-lg border transition-all hover:border-gold/30"
      style={{ borderColor: 'var(--border-default)', color: 'var(--text-secondary)' }}
      title={dark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
    >
      {dark ? '☀️' : '🌙'}
    </button>
  );
}

export default function App() {
  const [tab, setTab] = useState('simulator');
  const [dark, setDark] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('maiat-playground-theme');
      if (saved) return saved === 'dark';
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    return true;
  });
  const [params, setParams] = useState({
    trustThreshold: 50,
    autoApproveThreshold: 70,
    escrowThreshold: 30,
    quorumSize: 3,
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
    localStorage.setItem('maiat-playground-theme', dark ? 'dark' : 'light');
  }, [dark]);

  return (
    <>
      <div className="atmosphere" />

      <div className="min-h-screen">
        {/* Header */}
        <header className="liquid-glass sticky top-0 z-50">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-lg sm:text-xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                  <span style={{ color: 'var(--primary-gold, #D4A853)' }}>Maiat8183</span> Evaluator Playground
                </h1>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  Interactive ERC-8183 Hook Pipeline Simulator
                </p>
              </div>
              <ThemeToggle dark={dark} onToggle={() => setDark(!dark)} />
            </div>

            {/* Tabs */}
            <nav className="flex gap-1 mt-4 -mb-px">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`text-xs px-4 py-2 rounded-lg transition-all ${
                    tab === t.id
                      ? 'bg-gold/10 font-semibold'
                      : 'hover:bg-gold/5'
                  }`}
                  style={{
                    color: tab === t.id ? 'var(--primary-gold, #D4A853)' : 'var(--text-muted)',
                    border: tab === t.id ? '1px solid rgba(212, 168, 83, 0.2)' : '1px solid transparent',
                  }}
                >
                  {t.label}
                </button>
              ))}
            </nav>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
          {tab === 'simulator' && (
            <PipelineSimulator params={params} onParamsChange={setParams} />
          )}
          {tab === 'synthesis' && <SynthesisReplay />}
          {tab === 'compare' && <CompareMode />}
        </main>

        {/* Footer */}
        <footer className="py-8 text-center" style={{ borderTop: '1px solid var(--border-default)' }}>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Built by{' '}
            <a
              href="https://app.maiat.io"
              target="_blank"
              rel="noopener"
              className="underline transition-colors hover:text-gold"
              style={{ color: 'var(--primary-gold, #D4A853)' }}
            >
              Maiat Protocol
            </a>
            {' · '}
            <a
              href="https://github.com/JhiNResH/maiat8183"
              target="_blank"
              rel="noopener"
              className="underline transition-colors hover:text-gold"
              style={{ color: 'var(--text-secondary)' }}
            >
              GitHub
            </a>
            {' · '}
            <a
              href="https://passport.maiat.io"
              target="_blank"
              rel="noopener"
              className="underline transition-colors hover:text-gold"
              style={{ color: 'var(--text-secondary)' }}
            >
              Passport
            </a>
          </p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>
            Trust infrastructure for agent-to-agent transactions
          </p>
        </footer>
      </div>
    </>
  );
}
