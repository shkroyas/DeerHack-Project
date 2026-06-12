import React from 'react';
import type { Alert } from '@types/alert.types';
import { SeverityIndicator } from '@components/common/SeverityIndicator';
import { CRSGauge } from '@components/common/CRSGauge';
import { MITRETag } from '@components/common/MITRETag';

interface Props {
  /** Selected alert. */
  alert: Alert | null;
  /** Close handler. */
  onClose: () => void;
}

export const AlertDetailDrawer: React.FC<Props> = ({ alert, onClose }) => {
  if (!alert) return null;
  return (
    <div className="fixed inset-y-0 right-0 w-[580px] bg-background-elevated border-l border-background-border p-4 overflow-auto">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-text.secondary">Alert</div>
          <div className="text-text.primary font-semibold">{alert.id}</div>
        </div>
        <button onClick={onClose} className="px-2 py-1 text-xs bg-background-border rounded">Close</button>
      </div>
      <div className="mt-4 space-y-3">
        <SeverityIndicator severity={alert.severity} />
        <div className="text-xs text-text.secondary">{new Date(alert.timestamp).toLocaleString()}</div>
        <div className="text-xs text-text.secondary font-mono">{alert.sourceIp} → {alert.destinationIp ?? '-'}</div>
        {alert.mitre && <MITRETag technique={alert.mitre} />}
        <CRSGauge value={alert.crs} />
      </div>
    </div>
  );
};
