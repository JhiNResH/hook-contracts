import React from 'react';

const RESULT_CONFIG = {
  pass: { dot: '#10b981', label: 'PASS' },
  blocked: { dot: '#ef4444', label: 'BLOCKED' },
  warn: { dot: '#f59e0b', label: 'ESCROW' },
};

export default function HookStep({ hook, animate, delay }) {
  const cfg = RESULT_CONFIG[hook.result] || RESULT_CONFIG.pass;

  return (
    <div
      className={`rounded-lg p-3 transition-all ${animate ? 'hook-animate' : ''}`}
      style={{
        background: 'var(--hover-bg)',
        animationDelay: animate ? `${delay}ms` : undefined,
      }}
    >
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: cfg.dot }} />
          <span className="text-[11px] font-bold font-mono" style={{ color: 'var(--text-color)' }}>
            {hook.hook}
          </span>
          <span className="text-[8px] font-bold uppercase tracking-[0.15em] px-1.5 py-0.5 rounded"
            style={{ background: 'var(--badge-bg)', color: 'var(--text-muted)' }}>
            {hook.timing}
          </span>
        </div>
        <span className="text-[8px] font-bold uppercase tracking-[0.1em] px-2 py-0.5 rounded-full"
          style={{ color: cfg.dot, background: `${cfg.dot}12`, border: `1px solid ${cfg.dot}20` }}>
          {cfg.label}
        </span>
      </div>
      <p className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>{hook.action}</p>
      <p className="text-[10px] font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>{hook.detail}</p>
    </div>
  );
}
