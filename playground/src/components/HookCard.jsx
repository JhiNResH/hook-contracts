import React from 'react';

const STATUS_CONFIG = {
  pass: { label: 'PASS', dot: '#10b981' },
  blocked: { label: 'BLOCKED', dot: '#ef4444' },
  warn: { label: 'ESCROW', dot: '#f59e0b' },
};

export default function HookCard({ step, index, animate }) {
  const cfg = STATUS_CONFIG[step.status];

  return (
    <div
      className={`rounded-xl p-5 transition-all ${animate ? 'hook-animate' : ''}`}
      style={{
        animationDelay: animate ? `${index * 350}ms` : undefined,
        background: 'var(--card-bg)',
        border: '1px solid var(--border-color)',
      }}
    >
      {/* Header row */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full" style={{ background: cfg.dot }} />
          <span className="text-xs font-bold uppercase tracking-[0.08em]" style={{ color: 'var(--text-color)' }}>
            {step.name}
          </span>
        </div>
        <span
          className="text-[9px] font-bold uppercase tracking-[0.1em] px-2.5 py-1 rounded-full"
          style={{
            color: cfg.dot,
            background: `${cfg.dot}10`,
            border: `1px solid ${cfg.dot}25`,
          }}
        >
          {cfg.label}
        </span>
      </div>

      {/* Description */}
      <p className="text-[11px] mb-4" style={{ color: 'var(--text-muted)' }}>
        {step.description}
      </p>

      {/* Data grid */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 mb-4">
        {Object.entries(step.data).map(([key, val]) => (
          <div key={key} className="flex justify-between text-[11px]">
            <span style={{ color: 'var(--text-muted)' }}>{key}</span>
            <span className="font-mono font-medium" style={{ color: 'var(--text-color)' }}>{val}</span>
          </div>
        ))}
      </div>

      {/* Reason */}
      <div
        className="text-[11px] px-3 py-2 rounded-lg"
        style={{ background: 'var(--hover-bg)', color: 'var(--text-secondary)' }}
      >
        {step.reason}
      </div>
    </div>
  );
}
