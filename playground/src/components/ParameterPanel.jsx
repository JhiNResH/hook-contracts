import React from 'react';

function Slider({ label, value, onChange, min = 0, max = 100, step = 1 }) {
  return (
    <div className="mb-5">
      <div className="flex justify-between items-center mb-2">
        <label className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{label}</label>
        <span className="text-xs font-mono font-bold" style={{ color: 'var(--primary-gold, #D4A853)' }}>{value}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full"
      />
      <div className="flex justify-between mt-1">
        <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{min}</span>
        <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{max}</span>
      </div>
    </div>
  );
}

export default function ParameterPanel({ params, onChange }) {
  const update = (key) => (val) => onChange({ ...params, [key]: val });

  return (
    <div className="card p-5">
      <h3 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
        <span>⚙️</span> Parameters
      </h3>

      <Slider
        label="Trust Gate Threshold"
        value={params.trustThreshold}
        onChange={update('trustThreshold')}
      />
      <Slider
        label="Auto-Approve Threshold"
        value={params.autoApproveThreshold}
        onChange={update('autoApproveThreshold')}
      />
      <Slider
        label="Escrow Threshold"
        value={params.escrowThreshold}
        onChange={update('escrowThreshold')}
      />
      <Slider
        label="Quorum Size"
        value={params.quorumSize}
        onChange={update('quorumSize')}
        min={1}
        max={5}
      />

      <div className="mt-4 pt-4" style={{ borderTop: '1px solid var(--border-default)' }}>
        <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
          Adjust parameters to see how different configurations affect the hook pipeline.
          Changes apply instantly.
        </p>
      </div>
    </div>
  );
}
