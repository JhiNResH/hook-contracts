import React, { useState, useEffect, useRef, useCallback } from 'react';
import { generateSynthesisRounds } from '../lib/synthesis-data.js';

function JudgeCard({ judge }) {
  const pct = judge.trustScore;
  const dotColor = judge.blocked ? '#ef4444' : pct >= 70 ? '#10b981' : pct >= 50 ? '#f59e0b' : '#3b82f6';
  const statusText = judge.blocked ? 'BLOCKED' : pct >= 70 ? 'AUTO-APPROVED' : pct >= 50 ? 'TRUSTED' : 'ESCROW';

  return (
    <div
      className={`rounded-xl p-4 transition-all ${judge.blocked ? 'opacity-40' : ''}`}
      style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: dotColor }} />
          <span className="text-xs font-bold font-mono" style={{ color: 'var(--text-color)' }}>{judge.id}</span>
          <span
            className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-full"
            style={{
              color: judge.quality === 'good' ? '#10b981' : '#ef4444',
              background: judge.quality === 'good' ? '#10b98110' : '#ef444410',
            }}
          >
            {judge.quality}
          </span>
        </div>
        <span className="text-[9px] font-bold uppercase tracking-wider" style={{ color: dotColor }}>{statusText}</span>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border-color)' }}>
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${pct}%`, background: dotColor }}
        />
      </div>

      <div className="flex justify-between mt-1.5 text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
        <span>{judge.trustScore}/100</span>
        <span>{judge.attestations} att.</span>
      </div>
    </div>
  );
}

export default function SynthesisReplay() {
  const [rounds] = useState(() => generateSynthesisRounds());
  const [currentRound, setCurrentRound] = useState(0);
  const [playing, setPlaying] = useState(false);
  const intervalRef = useRef(null);

  useEffect(() => {
    if (playing) {
      intervalRef.current = setInterval(() => {
        setCurrentRound((r) => {
          if (r >= rounds.length - 1) { setPlaying(false); return r; }
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
      {/* Controls */}
      <div className="rounded-xl p-5 mb-6" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold" style={{ color: 'var(--text-color)' }}>Synthesis Simulation</h3>
            <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
              569 projects · 10 judges (7 good, 3 bad) · 5 rounds
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => { setPlaying(false); setCurrentRound(0); }}
              className="text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-full transition-colors"
              style={{ border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
              Reset
            </button>
            <button onClick={() => setPlaying(!playing)}
              className="text-[10px] font-bold uppercase tracking-wider px-4 py-1.5 rounded-full transition-colors"
              style={{ background: 'var(--text-color)', color: 'var(--bg-color)' }}>
              {playing ? 'Pause' : 'Play'}
            </button>
            <button onClick={() => setCurrentRound((r) => Math.min(r + 1, rounds.length - 1))}
              disabled={currentRound >= rounds.length - 1}
              className="text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-full transition-colors disabled:opacity-30"
              style={{ border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
              Step
            </button>
          </div>
        </div>

        {/* Round progress */}
        <div className="flex gap-2 mt-4">
          {rounds.map((_, i) => (
            <button
              key={i}
              onClick={() => { setPlaying(false); setCurrentRound(i); }}
              className="flex-1 h-1.5 rounded-full transition-all cursor-pointer"
              style={{ background: i <= currentRound ? 'var(--text-color)' : 'var(--border-color)' }}
            />
          ))}
        </div>
        <p className="text-center mt-2 text-[11px] font-mono font-bold" style={{ color: 'var(--text-color)' }}>
          Round {round.round} / 5
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Attestations', value: round.totalAttestations, color: '#3b82f6' },
          { label: 'Escrows', value: round.totalEscrows, color: '#f59e0b' },
          { label: 'Auto-Approved', value: round.autoApproved, color: '#10b981' },
          { label: 'Blocked', value: round.totalBlocks, color: '#ef4444' },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl p-4 text-center" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
            <div className="text-2xl font-bold font-mono" style={{ color }}>{value}</div>
            <div className="text-[10px] uppercase tracking-wider font-bold mt-1" style={{ color: 'var(--text-muted)' }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Judge cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {round.judges.map((j) => <JudgeCard key={j.id} judge={j} />)}
      </div>
    </div>
  );
}
