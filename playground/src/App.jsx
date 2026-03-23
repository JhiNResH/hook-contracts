import React, { useState, useEffect } from 'react';
import PipelineSimulator from './components/PipelineSimulator.jsx';
import SynthesisReplay from './components/SynthesisReplay.jsx';
import CompareMode from './components/CompareMode.jsx';

const TABS = [
  { id: 'simulator', label: 'Simulator' },
  { id: 'synthesis', label: 'Synthesis Replay' },
  { id: 'compare', label: 'Compare' },
];

export default function App() {
  const [tab, setTab] = useState('simulator');
  const [dark, setDark] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('maiat-playground-theme');
      if (saved) return saved === 'dark';
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    return false;
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
        {/* Navbar — pill style matching app.maiat.io */}
        <nav className="sticky top-0 z-50 px-4 pt-4">
          <div className="max-w-5xl mx-auto liquid-glass rounded-2xl px-6 py-3 flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs" style={{ background: 'var(--badge-bg)', border: '1px solid var(--border-color)' }}>
                🔬
              </div>
              <span className="font-bold text-sm tracking-tight" style={{ color: 'var(--text-color)' }}>
                maiat<span style={{ color: 'var(--text-muted)' }}>8183</span>
              </span>
            </div>

            {/* Nav Links — uppercase, spaced, small */}
            <div className="hidden sm:flex items-center gap-1">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className="px-4 py-1.5 rounded-full text-[10px] font-bold uppercase tracking-[0.15em] transition-colors"
                  style={{
                    color: tab === t.id ? 'var(--nav-active)' : 'var(--nav-inactive)',
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Theme toggle */}
            <button
              onClick={() => setDark(!dark)}
              className="w-8 h-8 rounded-full flex items-center justify-center transition-colors"
              style={{ background: 'var(--badge-bg)', border: '1px solid var(--border-color)' }}
            >
              <span className="text-sm">{dark ? '☀️' : '🌙'}</span>
            </button>
          </div>

          {/* Mobile tabs */}
          <div className="sm:hidden flex gap-1 mt-3 max-w-5xl mx-auto">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className="flex-1 py-2 rounded-xl text-[9px] font-bold uppercase tracking-[0.1em] transition-colors"
                style={{
                  color: tab === t.id ? 'var(--nav-active)' : 'var(--nav-inactive)',
                  background: tab === t.id ? 'var(--badge-bg)' : 'transparent',
                }}
              >
                {t.label}
              </button>
            ))}
          </div>
        </nav>

        {/* Hero */}
        <div className="max-w-5xl mx-auto px-4 pt-12 pb-6 text-center">
          <h1 className="atmosphere-text text-4xl sm:text-6xl md:text-7xl">
            Evaluator<br />Playground.
          </h1>
          <p className="mt-4 text-sm" style={{ color: 'var(--text-secondary)' }}>
            Interactive ERC-8183 hook pipeline simulator.{' '}
            <span style={{ color: 'var(--text-muted)' }}>Try different agents and parameters.</span>
          </p>
        </div>

        {/* Main Content */}
        <main className="max-w-5xl mx-auto px-4 pb-16">
          {tab === 'simulator' && (
            <PipelineSimulator params={params} onParamsChange={setParams} />
          )}
          {tab === 'synthesis' && <SynthesisReplay />}
          {tab === 'compare' && <CompareMode />}
        </main>

        {/* Footer — matching app.maiat.io layout */}
        <footer className="border-t" style={{ borderColor: 'var(--border-color)' }}>
          <div className="max-w-5xl mx-auto px-4 py-12">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-8">
              {/* Brand */}
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px]" style={{ background: 'var(--badge-bg)', border: '1px solid var(--border-color)' }}>🔬</div>
                  <span className="font-bold text-sm" style={{ color: 'var(--text-color)' }}>maiat</span>
                </div>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  Trust infrastructure for agent economy.
                </p>
              </div>

              {/* Product */}
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-[0.15em] mb-3" style={{ color: 'var(--text-color)' }}>Product</h4>
                <div className="space-y-2">
                  <a href="https://app.maiat.io" target="_blank" rel="noopener" className="block text-xs transition-colors hover:underline" style={{ color: 'var(--text-secondary)' }}>Dashboard</a>
                  <a href="https://passport.maiat.io" target="_blank" rel="noopener" className="block text-xs transition-colors hover:underline" style={{ color: 'var(--text-secondary)' }}>Passport</a>
                </div>
              </div>

              {/* Developers */}
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-[0.15em] mb-3" style={{ color: 'var(--text-color)' }}>Developers</h4>
                <div className="space-y-2">
                  <a href="https://github.com/JhiNResH/maiat8183" target="_blank" rel="noopener" className="block text-xs transition-colors hover:underline" style={{ color: 'var(--text-secondary)' }}>GitHub</a>
                  <a href="https://github.com/JhiNResH/maiat-protocol" target="_blank" rel="noopener" className="block text-xs transition-colors hover:underline" style={{ color: 'var(--text-secondary)' }}>Protocol</a>
                </div>
              </div>

              {/* Get Started */}
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-[0.15em] mb-3" style={{ color: 'var(--text-color)' }}>ERC-8183</h4>
                <p className="text-xs mb-3" style={{ color: 'var(--text-secondary)' }}>
                  Hook contracts for agentic commerce.
                </p>
                <a href="https://eips.ethereum.org/EIPS/eip-8183" target="_blank" rel="noopener"
                   className="inline-block text-[10px] font-bold uppercase tracking-[0.1em] px-4 py-2 rounded-full transition-colors"
                   style={{ background: 'var(--text-color)', color: 'var(--bg-color)' }}>
                  View EIP
                </a>
              </div>
            </div>

            <div className="mt-10 pt-6 flex items-center justify-between text-[10px]" style={{ borderTop: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
              <span>© 2026 Maiat Protocol. All rights reserved.</span>
              <span>MIT License</span>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
}
