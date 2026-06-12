import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { alertsService } from '@services/alerts.service';
import { queryKeys } from '@lib/queryKeys';
import type { Alert } from '@types/alert.types';
import { AlertFilters } from './AlertFilters';
import { AlertTable } from './AlertTable';
import { AlertDetailDrawer } from './AlertDetailDrawer';

const AlertsPage: React.FC = () => {
  const { data } = useQuery({
    queryKey: queryKeys.alerts.all,
    queryFn: () => alertsService.getAlerts({ page: 1, perPage: 50 }),
    refetchInterval: 5000
  });
  const [selected, setSelected] = useState<Alert | null>(null);

  return (
    <div className="grid grid-cols-4 gap-4 p-4">
      <div className="col-span-1">
        <AlertFilters count={0} onClear={() => null} />
      </div>
      <div className="col-span-3">
        <AlertTable alerts={data?.data ?? []} onAlertClick={(id) => setSelected(data?.data.find((a) => a.id === id) ?? null)} />
      </div>
      <AlertDetailDrawer alert={selected} onClose={() => setSelected(null)} />
    </div>
  );
};

export default AlertsPage;
