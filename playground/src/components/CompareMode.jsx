import React, { useState } from 'react';
import PipelineSimulator from './PipelineSimulator.jsx';
import ParameterPanel from './ParameterPanel.jsx';

const DEFAULT_PARAMS_A = { trustThreshold: 50, autoApproveThreshold: 70, escrowThreshold: 30, quorumSize: 3 };
const DEFAULT_PARAMS_B = { trustThreshold: 30, autoApproveThreshold: 50, escrowThreshold: 15, quorumSize: 2 };

export default function CompareMode() {
  const [paramsA, setParamsA] = useState(DEFAULT_PARAMS_A);
  const [paramsB, setParamsB] = useState(DEFAULT_PARAMS_B);

  return (
    <div>
      <div className="card p-4 mb-6 text-center">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
          ⚖️ Compare Mode
        </h3>
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
          Same agent, different parameters — see how configuration changes affect outcomes
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Config A */}
        <div>
          <div className="text-xs font-bold mb-3 text-center px-3 py-1.5 rounded-full bg-blue-500/10 text-blue-500 border border-blue-500/20 inline-block">
            Configuration A (Default)
          </div>
          <div className="mb-4">
            <ParameterPanel params={paramsA} onChange={setParamsA} />
          </div>
          <PipelineSimulator params={paramsA} onParamsChange={setParamsA} compare={true} />
        </div>

        {/* Config B */}
        <div>
          <div className="text-xs font-bold mb-3 text-center px-3 py-1.5 rounded-full bg-purple-500/10 text-purple-500 border border-purple-500/20 inline-block">
            Configuration B (Relaxed)
          </div>
          <div className="mb-4">
            <ParameterPanel params={paramsB} onChange={setParamsB} />
          </div>
          <PipelineSimulator params={paramsB} onParamsChange={setParamsB} compare={true} />
        </div>
      </div>
    </div>
  );
}
