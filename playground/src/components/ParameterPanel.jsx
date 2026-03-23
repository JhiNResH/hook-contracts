import React from 'react';

function Slider({ label, value, onChange, min = 0, max = 100, step = 1 }) {
  return (
    <div className="mb-5">
      <div className="flex justify-between items-center mb-2">
        <span className="text-[10px] font-bold uppercase tracking-[0.1em]" style={{ color: 'var(--text-muted)' }}>
          {label}
        </span>
        <span className="text-xs font-mono font-bold" style={{ color: 'var(--text-color)' }}>
          {value}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </div>
  );
}

export default function ParameterPanel({ params, onChange }) {
  const update = (key) => (val) => onChange({ ...params, [key]: val });

  return (
    <div className="rounded-xl p-5" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
      <h3 className="text-[10px] font-bold uppercase tracking-[0.15em] mb-5" style={{ color: 'var(--text-color)' }}>
        Parameters
      </h3>

      <Slider label="Trust Gate Threshold" value={params.trustThreshold} onChange={update('trustThreshold')} />
      <Slider label="Auto-Approve" value={params.autoApproveThreshold} onChange={update('autoApproveThreshold')} />
      <Slider label="Escrow Threshold" value={params.escrowThreshold} onChange={update('escrowThreshold')} />
      <Slider label="Quorum Size" value={params.quorumSize} onChange={update('quorumSize')} min={1} max={5} />

      <p className="text-[10px] mt-2 pt-3" style={{ color: 'var(--text-muted)', borderTop: '1px solid var(--border-color)' }}>
        Changes apply instantly to the pipeline simulation.
      </p>
    </div>
  );
}
