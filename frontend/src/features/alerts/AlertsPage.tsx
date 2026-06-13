import React, { useState } from 'react';
import { useAlertStore } from '@stores/alertStore';
import type { Alert } from '@types/alert.types';
import { AlertFilters } from './AlertFilters';
import { AlertTable } from './AlertTable';
import { AlertDetailDrawer } from './AlertDetailDrawer';

const AlertsPage: React.FC = () => {
  const alerts = useAlertStore((state) => state.alerts);
  const [selected, setSelected] = useState<Alert | null>(null);

  // In-memory pagination could be added here if needed, 
  // but for live feed we can just slice the most recent ones.
  const displayAlerts = alerts.slice(0, 50);

  return (
    <div className="flex flex-col lg:grid lg:grid-cols-4 gap-4 p-4">
      <div className="lg:col-span-1">
        <AlertFilters count={alerts.length} onClear={() => null} />
      </div>
      <div className="lg:col-span-3">
        <AlertTable alerts={displayAlerts} onAlertClick={(id) => setSelected(alerts.find((a) => a.id === id) ?? null)} />
      </div>
      <AlertDetailDrawer alert={selected} onClose={() => setSelected(null)} />
    </div>
  );
};

export default AlertsPage;
