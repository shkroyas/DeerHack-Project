import React from 'react';
import type { Alert } from '@types/alert.types';
import { SeverityIndicator } from '@components/common/SeverityIndicator';
import { CRSGauge } from '@components/common/CRSGauge';
import { MITRETag } from '@components/common/MITRETag';

interface Props {
  /** Alerts list. */
  alerts: Alert[];
  /** Row click. */
  onAlertClick?: (id: string) => void;
}

export const AlertTable: React.FC<Props> = ({ alerts, onAlertClick }) => {
  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="grid grid-cols-6 text-xs text-text.secondary mb-2">
        <div>Severity</div>
        <div>Timestamp</div>
        <div>Source IP</div>
        <div>MITRE</div>
        <div>CRS</div>
        <div>Status</div>
      </div>
      <div className="space-y-2 max-h-96 overflow-auto">
        {alerts.map((a) => (
          <button
            key={a.id}
            onClick={() => onAlertClick?.(a.id)}
            className="w-full text-left grid grid-cols-6 items-center p-2 bg-background-border rounded"
          >
            <SeverityIndicator severity={a.severity} />
            <span className="text-xs text-text.secondary">{new Date(a.timestamp).toLocaleString()}</span>
            <span className="text-xs text-text.secondary font-mono">{a.sourceIp}</span>
            <span><MITRETag technique={a.mitre} severity={a.severity} /></span>
            <CRSGauge value={a.crs} />
            <span className="text-xs text-text.secondary">OPEN</span>
          </button>
        ))}
      </div>
    </div>
  );
};
