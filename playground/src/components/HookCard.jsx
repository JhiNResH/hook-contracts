import React from 'react';

const STATUS_CONFIG = {
  pass: { icon: '✅', label: 'PASS', color: 'text-emerald-500', border: 'border-emerald-500/20', bg: 'bg-emerald-500/5' },
  blocked: { icon: '❌', label: 'BLOCKED', color: 'text-red-500', border: 'border-red-500/20', bg: 'bg-red-500/5' },
  warn: { icon: '⚠️', label: 'ESCROW / ESCALATE', color: 'text-amber-500', border: 'border-amber-500/20', bg: 'bg-amber-500/5' },
};

export default function HookCard({ step, index, animate }) {
  const cfg = STATUS_CONFIG[step.status];

  return (
    <div
      className={`card p-5 ${animate ? 'hook-card-animate' : ''}`}
      style={animate ? { animationDelay: `${index * 400}ms` } : {}}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className="text-lg">{cfg.icon}</span>
          <h3 className="font-mono font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
            {step.name}
          </h3>
        </div>
        <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${cfg.color} ${cfg.bg} ${cfg.border} border`}>
          {cfg.label}
        </span>
      </div>

      <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
        {step.description}
      </p>

      <div className="grid grid-cols-2 gap-2 mb-3">
        {Object.entries(step.data).map(([key, val]) => (
          <div key={key} className="text-xs">
            <span style={{ color: 'var(--text-muted)' }}>{key}: </span>
            <span className="font-mono font-medium" style={{ color: 'var(--text-secondary)' }}>{val}</span>
          </div>
        ))}
      </div>

      <div className={`text-xs p-2.5 rounded-lg ${cfg.bg} border ${cfg.border}`}>
        <span className={cfg.color}>{step.reason}</span>
      </div>
    </div>
  );
}
