import React, { useState, useMemo, useEffect } from 'react';
import { runPipeline } from '../lib/simulation.js';
import { PRESETS, VALUE_TIERS, TOKENS, shortenAddress } from '../lib/utils.js';
import HookCard from './HookCard.jsx';
import ParameterPanel from './ParameterPanel.jsx';

const VERDICT_CONFIG = {
  approved: { label: 'APPROVED', emoji: '✅', glow: 'glow-green', color: 'text-emerald-500', border: 'border-emerald-500/30' },
  rejected: { label: 'REJECTED', emoji: '❌', glow: 'glow-red', color: 'text-red-500', border: 'border-red-500/30' },
  escalated: { label: 'ESCALATED', emoji: '⚠️', glow: 'glow-amber', color: 'text-amber-500', border: 'border-amber-500/30' },
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

  useEffect(() => {
    setAnimKey((k) => k + 1);
  }, [address, overrideScore, valueTier, paymentToken, params]);

  const vc = VERDICT_CONFIG[result.verdict];

  const handlePreset = (preset) => {
    setAddress(preset.address);
    setOverrideScore(preset.score);
  };

  const handleCustomAddress = (addr) => {
    setAddress(addr);
    setOverrideScore(null);
  };

  return (
    <div className={`flex flex-col lg:flex-row gap-6 ${compare ? '' : ''}`}>
      {/* Main Pipeline */}
      <div className="flex-1 min-w-0">
        {/* Input Section */}
        <div className="card p-5 mb-6">
          <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            🔍 Agent & Job Configuration
          </h3>

          {/* Presets */}
          <div className="flex flex-wrap gap-2 mb-4">
            {PRESETS.map((p) => (
              <button
                key={p.label}
                onClick={() => handlePreset(p)}
                className={`text-xs px-3 py-1.5 rounded-full border transition-all ${
                  address === p.address
                    ? 'border-gold/50 bg-gold/10 text-gold-light'
                    : 'border-[var(--border-default)] hover:border-gold/30'
                }`}
                style={address !== p.address ? { color: 'var(--text-secondary)' } : {}}
              >
                {p.label} ({p.score})
              </button>
            ))}
          </div>

          {/* Custom address */}
          <div className="mb-4">
            <input
              type="text"
              value={address}
              onChange={(e) => handleCustomAddress(e.target.value)}
              placeholder="0x..."
              className="w-full px-3 py-2 rounded-lg text-xs font-mono border outline-none focus:border-gold/50 transition-colors"
              style={{
                background: 'var(--bg-elevated)',
                borderColor: 'var(--border-default)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          {/* Job params */}
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="text-[10px] block mb-1" style={{ color: 'var(--text-muted)' }}>Value Tier</label>
              <select
                value={valueTier}
                onChange={(e) => setValueTier(e.target.value)}
                className="w-full px-2 py-1.5 rounded-lg text-xs border outline-none"
                style={{
                  background: 'var(--bg-elevated)',
                  borderColor: 'var(--border-default)',
                  color: 'var(--text-primary)',
                }}
              >
                {VALUE_TIERS.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <div className="flex-1">
              <label className="text-[10px] block mb-1" style={{ color: 'var(--text-muted)' }}>Payment Token</label>
              <select
                value={paymentToken}
                onChange={(e) => setPaymentToken(e.target.value)}
                className="w-full px-2 py-1.5 rounded-lg text-xs border outline-none"
                style={{
                  background: 'var(--bg-elevated)',
                  borderColor: 'var(--border-default)',
                  color: 'var(--text-primary)',
                }}
              >
                {TOKENS.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Pipeline Flow */}
        <div className="space-y-0" key={animKey}>
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
          className={`card p-6 text-center ${vc.glow} ${vc.border} border hook-card-animate`}
          style={{ animationDelay: `${result.steps.length * 400}ms` }}
        >
          <div className="text-3xl mb-2">{vc.emoji}</div>
          <div className={`text-xl font-bold font-mono ${vc.color}`}>{vc.label}</div>
          <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
            {result.verdict === 'approved' && 'All hooks passed — job proceeds with full trust'}
            {result.verdict === 'rejected' && 'One or more hooks blocked — job cannot proceed'}
            {result.verdict === 'escalated' && 'Job requires additional review (quorum or escrow)'}
          </p>
          <div className="text-xs font-mono mt-3" style={{ color: 'var(--text-secondary)' }}>
            Trust Score: {result.trustScore}/100 · Tier: {valueTier} · Token: {paymentToken}
          </div>
        </div>
      </div>

      {/* Parameter Panel (sidebar) */}
      {!compare && (
        <div className="w-full lg:w-72 shrink-0">
          <div className="lg:sticky lg:top-6">
            <ParameterPanel params={params} onChange={onParamsChange} />
          </div>
        </div>
      )}
    </div>
  );
}
