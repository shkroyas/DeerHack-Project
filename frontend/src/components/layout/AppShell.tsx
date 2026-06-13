import React, { useCallback } from 'react';
import { Outlet } from 'react-router-dom';
// Removed useUIStore
import { useAlertStore } from '@stores/alertStore';
import { useAlertStream } from '@hooks/useAlertStream';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

export const AppShell: React.FC = () => {
  // collapsed was here
  const addAlert = useAlertStore((s) => s.addAlert);

  // Stable callback to avoid infinite reconnection loops
  const handleAlert = useCallback((payload: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    if (payload && payload.record_id) {
      addAlert({
        id: `ALERT-${payload.record_id}`,
        timestamp: payload.timestamp || new Date().toISOString(),
        sourceIp: payload.src_ip || "Unknown",
        destinationIp: payload.dst_ip || "Unknown",
        severity: payload.priority || "LOW",
        mitre: payload.mitre_technique || payload.campaign_ticket_id || "Unknown",
        agents: payload.agents_fired || [],
        crs: payload.crs || 0.0,
        challenge: payload.challenge,
        label: payload.label,
        is_suppressed: payload.is_suppressed,
        suppression_reason: payload.suppression_reason
      });
    }
  }, [addAlert]);

  // Subscribe to live feed globally
  useAlertStream(handleAlert);

  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 overflow-y-auto bg-background-primary">
        <TopBar />
        <div className="p-4">
          <Outlet />
        </div>
      </main>
    </div>
  );
};

