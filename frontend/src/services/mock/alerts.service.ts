import { AlertListSchema } from '@types/alert.types';
import type { AlertFilters } from '@types/alert.types';

const mockAlerts = Array.from({ length: 50 }).map((_, i) => ({
  id: `ALERT-${1000 + i}`,
  timestamp: new Date(Date.now() - i * 60000).toISOString(),
  sourceIp: `192.168.1.${(i % 254) + 1}`,
  destinationIp: `10.0.0.${(i % 254) + 1}`,
  severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'QUEUED'][i % 5],
  mitre: ['T1071.001', 'T1046', 'T1213', 'T1021'][i % 4],
  agents: [i % 2 === 0 ? 'Packet' : 'Flow'],
  crs: Math.round(Math.random() * 100) / 100,
  challenge: ['C1', 'C2', 'C3', 'C4'][i % 4]
}));

export const alertsService = {
  getAlerts: async (filters: AlertFilters) => {
    const result = { data: mockAlerts.slice(0, 50), total: mockAlerts.length, page: 1 };
    return AlertListSchema.parse(result);
  },
  getAlertById: async (id: string) => {
    const found = mockAlerts.find((a) => a.id === id);
    if (!found) throw new Error('Not found');
    return found;
  },
  patchAck: async (id: string) => {
    const found = mockAlerts.find((a) => a.id === id);
    if (!found) throw new Error('Not found');
    // simulate ack by setting a status
    // return the alert
    return found;
  },
  bulkAck: async (ids: string[]) => {
    const updated = ids.filter((id) => mockAlerts.find((a) => a.id === id)).length;
    return { updated };
  }
};
