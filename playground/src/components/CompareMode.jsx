import React, { useState } from 'react';
import PipelineSimulator from './PipelineSimulator.jsx';
import ParameterPanel from './ParameterPanel.jsx';

export default function CompareMode() {
  const [paramsA, setParamsA] = useState({ trustThreshold: 50, autoApproveThreshold: 70, escrowThreshold: 30, quorumSize: 3 });
  const [paramsB, setParamsB] = useState({ trustThreshold: 30, autoApproveThreshold: 50, escrowThreshold: 15, quorumSize: 2 });

  return (
    <div>
      <div className="rounded-xl p-4 mb-6 text-center" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-color)' }}>
        <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          Same agent, different parameters — see how configuration changes affect outcomes.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-[0.15em] mb-3 text-center" style={{ color: 'var(--text-color)' }}>
            Configuration A <span style={{ color: 'var(--text-muted)' }}>· Default</span>
          </div>
          <div className="mb-4"><ParameterPanel params={paramsA} onChange={setParamsA} /></div>
          <PipelineSimulator params={paramsA} onParamsChange={setParamsA} compare={true} />
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-[0.15em] mb-3 text-center" style={{ color: 'var(--text-color)' }}>
            Configuration B <span style={{ color: 'var(--text-muted)' }}>· Relaxed</span>
          </div>
          <div className="mb-4"><ParameterPanel params={paramsB} onChange={setParamsB} /></div>
          <PipelineSimulator params={paramsB} onParamsChange={setParamsB} compare={true} />
        </div>
      </div>
    </div>
  );
}
