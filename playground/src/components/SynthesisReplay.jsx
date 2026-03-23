import React, { useState, useEffect, useRef, useCallback } from 'react';
import { generateSynthesisRounds } from '../lib/synthesis-data.js';

function JudgeCard({ judge, maxScore = 100 }) {
  const pct = (judge.trustScore / maxScore) * 100;
  const statusLabel = judge.blocked
    ? '❌ BLOCKED'
    : judge.trustScore >= 70
    ? '✅ AUTO-APPROVED'
    : judge.trustScore >= 50
    ? '🟡 TRUSTED'
    : '🔵 ESCROW';

  const barColor = judge.blocked
    ? 'bg-red-500'
    : judge.trustScore >= 70
    ? 'bg-emerald-500'
    : judge.trustScore >= 50
    ? 'bg-amber-500'
    : 'bg-blue-500';

  return (
    <div className={`card p-3 transition-all ${judge.blocked ? 'opacity-50' : ''}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
            {judge.id}
          </span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${judge.quality === 'good' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
            {judge.quality}
          </span>
        </div>
        <span className="text-[10px] font-medium" style={{ color: 'var(--text-secondary)' }}>
          {statusLabel}
        </span>
      </div>

      <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--border-default)' }}>
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="flex justify-between mt-1">
        <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
          Score: {judge.trustScore}/100
        </span>
        <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
          {judge.attestations} attestations
        </span>
      </div>
    </div>
  );
}

export default function SynthesisReplay() {
  const [rounds] = useState(() => generateSynthesisRounds());
  const [currentRound, setCurrentRound] = useState(0);
  const [playing, setPlaying] = useState(false);
  const intervalRef = useRef(null);

  const play = useCallback(() => {
    setPlaying(true);
  }, []);

  const pause = useCallback(() => {
    setPlaying(false);
  }, []);

  const stepForward = useCallback(() => {
    setCurrentRound((r) => Math.min(r + 1, rounds.length - 1));
  }, [rounds.length]);

  const reset = useCallback(() => {
    setPlaying(false);
    setCurrentRound(0);
  }, []);

  useEffect(() => {
    if (playing) {
      intervalRef.current = setInterval(() => {
        setCurrentRound((r) => {
          if (r >= rounds.length - 1) {
            setPlaying(false);
            return r;
          }
          return r + 1;
        });
      }, 2000);
    }
    return () => clearInterval(intervalRef.current);
  }, [playing, rounds.length]);

  const round = rounds[currentRound];
  if (!round) return null;

  return (
    <div>
      {/* Header */}
      <div className="card p-5 mb-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              🎮 Synthesis Simulation Replay
            </h3>
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              569 projects · 10 judges (7 good, 3 bad) · 5 rounds
            </p>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-2">
            <button
              onClick={reset}
              className="px-3 py-1.5 text-xs rounded-lg border transition-colors hover:border-gold/30"
              style={{ borderColor: 'var(--border-default)', color: 'var(--text-secondary)' }}
            >
              ⏮ Reset
            </button>
            {playing ? (
              <button
                onClick={pause}
                className="px-3 py-1.5 text-xs rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-500 transition-colors"
              >
                ⏸ Pause
              </button>
            ) : (
              <button
                onClick={play}
                className="px-3 py-1.5 text-xs rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-500 transition-colors"
              >
                ▶ Play
              </button>
            )}
            <button
              onClick={stepForward}
              disabled={currentRound >= rounds.length - 1}
              className="px-3 py-1.5 text-xs rounded-lg border transition-colors hover:border-gold/30 disabled:opacity-30"
              style={{ borderColor: 'var(--border-default)', color: 'var(--text-secondary)' }}
            >
              ⏭ Step
            </button>
          </div>
        </div>

        {/* Round indicator */}
        <div className="flex gap-2 mt-4">
          {rounds.map((_, i) => (
            <button
              key={i}
              onClick={() => { setPlaying(false); setCurrentRound(i); }}
              className={`flex-1 h-2 rounded-full transition-all ${
                i <= currentRound ? 'bg-gold' : ''
              }`}
              style={i > currentRound ? { background: 'var(--border-default)' } : {}}
            />
          ))}
        </div>
        <div className="text-center mt-2">
          <span className="text-xs font-mono font-bold" style={{ color: 'var(--primary-gold, #D4A853)' }}>
            Round {round.round} / 5
          </span>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'EAS Attestations', value: round.totalAttestations, color: 'text-blue-500' },
          { label: 'Escrow Txns', value: round.totalEscrows, color: 'text-amber-500' },
          { label: 'Auto-Approved', value: round.autoApproved, color: 'text-emerald-500' },
          { label: 'Judges Blocked', value: round.totalBlocks, color: 'text-red-500' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card p-3 text-center">
            <div className={`text-lg font-bold font-mono ${color}`}>{value}</div>
            <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Judge Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {round.judges.map((judge) => (
          <JudgeCard key={judge.id} judge={judge} />
        ))}
      </div>

      {/* Round Summary */}
      <div className="card p-4 mt-6">
        <h4 className="text-xs font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
          Round {round.round} Summary
        </h4>
        <div className="text-xs space-y-1" style={{ color: 'var(--text-secondary)' }}>
          <p>📋 {round.projectsEvaluated} projects evaluated</p>
          <p>🔒 {round.escrows} escrow transactions (FundTransferHook)</p>
          <p>✅ {round.autoApproved} auto-approved (TrustBasedEvaluator)</p>
          <p>👥 {round.escalated} multi-judge reviews (quorum consensus)</p>
          {round.newlyBlocked.length > 0 && (
            <p className="text-red-500">❌ Blocked: {round.newlyBlocked.join(', ')}</p>
          )}
        </div>
      </div>
    </div>
  );
}
