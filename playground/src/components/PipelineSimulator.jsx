import React, { useState, useMemo, useEffect } from 'react';
import { simulateProjectEvaluation } from '../lib/simulation.js';
import { JUDGE_PRESETS, PROJECT_PRESETS, shortenAddress } from '../lib/utils.js';
import HookStep from './HookCard.jsx';
import ParameterPanel from './ParameterPanel.jsx';

const VERDICT_DOT = {
  approved: '#10b981',
  escalated: '#f59e0b',
  blocked: '#ef4444',
  rejected: '#ef4444',
};

const VERDICT_LABEL = {
  approved: 'Auto-Approved',
  escalated: 'Needs Quorum',
  blocked: 'Blocked',
  rejected: 'Rejected',
};

export default function PipelineSimulator({ params, onParamsChange, compare }) {
  const [projectIdx, setProjectIdx] = useState(0);
  const [selectedJudge, setSelectedJudge] = useState(null);
  const [animKey, setAnimKey] = useState(0);

  const project = PROJECT_PRESETS[projectIdx];
  const result = useMemo(
    () => simulateProjectEvaluation({ project, judges: JUDGE_PRESETS, params }),
    [project, params]
  );

  useEffect(() => { setAnimKey(k => k + 1); }, [projectIdx, params]);

  const s = result.summary;
  const outcomeColor = s.quorumMet ? '#10b981' : s.approved + s.escalated >= (params.quorumSize || 3) ? '#f59e0b' : '#ef4444';
  const outcomeLabel = s.quorumMet ? 'Evaluation Complete' : s.projectOutcome === 'pending-quorum' ? 'Pending Quorum' : 'Insufficient Trusted Judges';

  return (
    <div className="flex flex-col lg:flex-row gap-6">
      <div className="flex-1 min-w-0">

        {/* Project selector */}
        <div className="rounded-xl p-5 mb-6" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
          <div className="text-[9px] font-bold uppercase tracking-[0.2em] mb-3" style={{ color: 'var(--text-muted)' }}>
            Project Requesting Evaluation
          </div>
          <div className="flex gap-2 mb-4">
            {PROJECT_PRESETS.map((p, i) => (
              <button key={p.name} onClick={() => setProjectIdx(i)}
                className="text-[10px] font-medium px-3 py-1.5 rounded-full transition-all"
                style={{
                  color: i === projectIdx ? 'var(--text-color)' : 'var(--text-muted)',
                  background: i === projectIdx ? 'var(--badge-bg)' : 'transparent',
                  border: `1px solid ${i === projectIdx ? 'var(--border-color)' : 'transparent'}`,
                }}>
                {p.name}
              </button>
            ))}
          </div>
          <p className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>{project.desc}</p>
          <p className="text-[10px] font-mono mt-1" style={{ color: 'var(--text-muted)' }}>Prize pool: {project.prize}</p>
        </div>

        {/* Judges overview */}
        <div className="text-[9px] font-bold uppercase tracking-[0.2em] mb-3" style={{ color: 'var(--text-muted)' }}>
          {JUDGE_PRESETS.length} Judges Attempting to Evaluate — Who Gets Through?
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-6" key={animKey}>
          {result.results.map((r, i) => {
            const dot = VERDICT_DOT[r.verdict];
            const isSelected = selectedJudge === i;
            return (
              <button
                key={r.judge.name}
                onClick={() => setSelectedJudge(isSelected ? null : i)}
                className={`text-left rounded-xl p-4 transition-all hook-animate ${isSelected ? 'ring-1' : ''}`}
                style={{
                  animationDelay: `${i * 100}ms`,
                  background: 'var(--card-bg)',
                  border: `1px solid ${isSelected ? dot : 'var(--border-color)'}`,
                  ringColor: dot,
                }}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ background: dot }} />
                    <span className="text-xs font-bold" style={{ color: 'var(--text-color)' }}>{r.judge.name}</span>
                  </div>
                  <span className="text-[8px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full"
                    style={{ color: dot, background: `${dot}12`, border: `1px solid ${dot}20` }}>
                    {VERDICT_LABEL[r.verdict]}
                  </span>
                </div>

                {/* Trust score bar */}
                <div className="h-1.5 rounded-full overflow-hidden mb-1.5" style={{ background: 'var(--border-color)' }}>
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${r.judgeScore}%`, background: dot }} />
                </div>

                <div className="flex justify-between text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                  <span>Trust: {r.judgeScore}/100</span>
                  <span>{r.judge.quality}</span>
                </div>
                <p className="text-[9px] mt-1" style={{ color: 'var(--text-muted)' }}>{r.judge.history}</p>
              </button>
            );
          })}
        </div>

        {/* Selected judge detail — hook pipeline */}
        {selectedJudge !== null && (
          <div className="rounded-xl p-5 mb-6" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
            <div className="text-[9px] font-bold uppercase tracking-[0.2em] mb-1" style={{ color: 'var(--text-muted)' }}>
              Hook Pipeline for {result.results[selectedJudge].judge.name}
            </div>
            <p className="text-[11px] mb-4" style={{ color: 'var(--text-secondary)' }}>
              MaiatRouterHook chains these plugins in priority order. <span className="font-mono">beforeAction</span> can revert (blocking). <span className="font-mono">afterAction</span> uses try/catch (non-blocking).
            </p>
            <div className="space-y-2">
              {result.results[selectedJudge].steps.map((hook, i) => (
                <HookStep key={i} hook={hook} animate={true} delay={i * 150} />
              ))}
            </div>
          </div>
        )}

        {/* Project outcome */}
        <div className="rounded-xl p-6 text-center" style={{
          background: 'var(--card-bg)',
          border: `1px solid ${outcomeColor}25`,
          boxShadow: `0 0 40px ${outcomeColor}08`,
        }}>
          <div className="flex items-center justify-center gap-3 mb-2">
            <div className="w-3 h-3 rounded-full" style={{ background: outcomeColor }} />
            <span className="atmosphere-text text-2xl sm:text-3xl">{outcomeLabel}.</span>
          </div>
          <div className="flex items-center justify-center gap-4 mt-3 text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
            <span>{s.approved} approved</span>
            <span>·</span>
            <span>{s.escalated} escalated</span>
            <span>·</span>
            <span>{s.blocked + s.rejected} blocked</span>
            <span>·</span>
            <span>quorum: {params.quorumSize || 3}</span>
          </div>
          <p className="text-[11px] mt-3 max-w-md mx-auto" style={{ color: 'var(--text-secondary)' }}>
            {s.quorumMet
              ? `${s.approved} trusted judges reached consensus. Every evaluation has an immutable EAS attestation. Reputation updated in EvaluatorRegistry.`
              : `Not enough trusted judges passed the hook pipeline. Project needs more qualified evaluators or lower thresholds.`
            }
          </p>
        </div>
      </div>

      {/* Sidebar */}
      {!compare && (
        <div className="w-full lg:w-64 shrink-0">
          <div className="lg:sticky lg:top-24">
            <ParameterPanel params={params} onChange={onParamsChange} />

            {/* Who watches the watchmen */}
            <div className="rounded-xl p-4 mt-4" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
              <div className="text-[9px] font-bold uppercase tracking-[0.2em] mb-2" style={{ color: 'var(--text-muted)' }}>
                How It Works
              </div>
              <div className="text-[10px] space-y-2" style={{ color: 'var(--text-secondary)' }}>
                <p>1. Projects submit for evaluation</p>
                <p>2. Judge agents apply to evaluate</p>
                <p>3. <strong>Maiat8183 hooks</strong> gate each judge:</p>
                <p className="pl-3 font-mono text-[9px]" style={{ color: 'var(--text-muted)' }}>
                  TrustGate → Escrow → Evaluator → Attestation → Mutual Review
                </p>
                <p>4. Trusted judges pass, untrusted get blocked</p>
                <p>5. Every evaluation = immutable EAS attestation</p>
                <p>6. Good judges earn trust, bad ones get delisted</p>
              </div>
            </div>

            {/* Architecture */}
            <div className="rounded-xl p-4 mt-4" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
              <div className="text-[9px] font-bold uppercase tracking-[0.2em] mb-2" style={{ color: 'var(--text-muted)' }}>
                Contract Architecture
              </div>
              <div className="text-[9px] font-mono space-y-1" style={{ color: 'var(--text-secondary)' }}>
                <p>AgenticCommerceHooked</p>
                <p className="pl-2">└ MaiatRouterHook</p>
                <p className="pl-5">├ TrustGateACPHook</p>
                <p className="pl-5">├ TokenSafetyHook</p>
                <p className="pl-5">├ FundTransferHook</p>
                <p className="pl-5">├ AttestationHook</p>
                <p className="pl-5">└ MutualAttestationHook</p>
                <p className="mt-1.5">TrustBasedEvaluator</p>
                <p>EvaluatorRegistry</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
