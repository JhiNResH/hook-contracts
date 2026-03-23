import React, { useState, useMemo, useEffect } from 'react';
import { runPipeline } from '../lib/simulation.js';
import { PRESETS, VALUE_TIERS, TOKENS } from '../lib/utils.js';
import HookCard from './HookCard.jsx';
import ParameterPanel from './ParameterPanel.jsx';

const VERDICT_CONFIG = {
  approved: { label: 'Approved', dot: '#10b981', desc: 'All hooks passed — job proceeds with full trust.' },
  rejected: { label: 'Rejected', dot: '#ef4444', desc: 'One or more hooks blocked — job cannot proceed.' },
  escalated: { label: 'Escalated', dot: '#f59e0b', desc: 'Requires additional review via quorum consensus.' },
};

export default function PipelineSimulator({ params, onParamsChange, compare }) {
  const [address, setAddress] = useState(PRESETS[0].address);
  const [overrideScore, setOverrideScore] = useState(PRESETS[0].score);
  const [valueTier, setValueTier] = useState('Medium');
  const [paymentToken, setPaymentToken] = useState('ETH');
  const [animKey, setAnimKey] = useState(0);

  const result = useMemo(
    () => runPipeline({ address, overrideScore, valueTier, paymentToken, params }),
    [address, overrideScore, valueTier, paymentToken, params]
  );

  useEffect(() => { setAnimKey((k) => k + 1); }, [address, overrideScore, valueTier, paymentToken, params]);

  const vc = VERDICT_CONFIG[result.verdict];

  return (
    <div className={`flex flex-col lg:flex-row gap-6`}>
      <div className="flex-1 min-w-0">
        {/* Input — search bar style like app.maiat.io verify page */}
        <div className="rounded-2xl p-1 mb-8" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)', boxShadow: 'var(--glass-shadow)' }}>
          <div className="flex items-center gap-3 px-4 py-3">
            <span className="text-lg" style={{ color: 'var(--text-muted)' }}>🔍</span>
            <input
              type="text"
              value={address}
              onChange={(e) => { setAddress(e.target.value); setOverrideScore(null); }}
              placeholder="0x... or agent name"
              className="flex-1 bg-transparent outline-none text-sm"
              style={{ color: 'var(--text-color)' }}
            />
            <div className="flex gap-2">
              <select
                value={valueTier}
                onChange={(e) => setValueTier(e.target.value)}
                className="text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-full outline-none cursor-pointer"
                style={{ background: 'var(--badge-bg)', color: 'var(--text-color)', border: '1px solid var(--border-color)' }}
              >
                {VALUE_TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
              <select
                value={paymentToken}
                onChange={(e) => setPaymentToken(e.target.value)}
                className="text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-full outline-none cursor-pointer"
                style={{ background: 'var(--badge-bg)', color: 'var(--text-color)', border: '1px solid var(--border-color)' }}
              >
                {TOKENS.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
          </div>

          {/* Preset buttons */}
          <div className="flex gap-2 px-4 pb-3">
            {PRESETS.map((p) => (
              <button
                key={p.label}
                onClick={() => { setAddress(p.address); setOverrideScore(p.score); }}
                className="text-[10px] font-medium px-3 py-1 rounded-full transition-all"
                style={{
                  color: address === p.address ? 'var(--text-color)' : 'var(--text-muted)',
                  background: address === p.address ? 'var(--badge-bg)' : 'transparent',
                  border: `1px solid ${address === p.address ? 'var(--border-color)' : 'transparent'}`,
                }}
              >
                {p.label} · {p.score}
              </button>
            ))}
          </div>
        </div>

        {/* Pipeline Flow */}
        <div key={animKey}>
          {result.steps.map((step, i) => (
            <div key={step.name}>
              <HookCard step={step} index={i} animate={true} />
              {i < result.steps.length - 1 && <div className="pipeline-connector" />}
            </div>
          ))}
        </div>

        {/* Final Verdict */}
        <div className="pipeline-connector" />
        <div
          className="rounded-xl p-8 text-center hook-animate"
          style={{
            animationDelay: `${result.steps.length * 350}ms`,
            background: 'var(--card-bg)',
            border: `1px solid ${vc.dot}25`,
            boxShadow: `0 0 40px ${vc.dot}08`,
          }}
        >
          <div className="flex items-center justify-center gap-3 mb-2">
            <div className="w-3 h-3 rounded-full" style={{ background: vc.dot }} />
            <span className="atmosphere-text text-3xl sm:text-4xl">{vc.label}.</span>
          </div>
          <p className="text-xs mt-2" style={{ color: 'var(--text-secondary)' }}>{vc.desc}</p>
          <div className="flex items-center justify-center gap-4 mt-4 text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
            <span>Score {result.trustScore}/100</span>
            <span>·</span>
            <span>{valueTier} tier</span>
            <span>·</span>
            <span>{paymentToken}</span>
          </div>
        </div>
      </div>

      {/* Sidebar */}
      {!compare && (
        <div className="w-full lg:w-64 shrink-0">
          <div className="lg:sticky lg:top-24">
            <ParameterPanel params={params} onChange={onParamsChange} />
          </div>
        </div>
      )}
    </div>
  );
}
