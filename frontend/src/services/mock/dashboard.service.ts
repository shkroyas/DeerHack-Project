import { DashboardGraphSchema, DashboardKpiSchema } from '@types/dashboard.types';

export const dashboardService = {
  getKpis: async () => {
    await new Promise((r) => setTimeout(r, 150));
    return DashboardKpiSchema.parse({
      threatsToday: 123,
      falsePositiveRate: 7.1,
      intelFeedAgeMin: 12,
      meanResponseTimeMin: 4.2
    });
  },
  getGraph: async () => {
    await new Promise((r) => setTimeout(r, 200));
    const data = {
      nodes: [
        { data: { id: 'n1', label: 'WORKSTATION-1', type: 'WORKSTATION', ip: '10.0.1.12', state: 'safe' } },
        { data: { id: 'n2', label: 'CORE_DB', type: 'CORE_BANKING_DB', ip: '10.0.2.5', state: 'safe' } },
        { data: { id: 'n3', label: 'C2-1', type: 'C2_SERVER', ip: '203.0.113.45', state: 'suspicious' } }
      ],
      edges: [
        { data: { id: 'e1', source: 'n1', target: 'n2', type: 'normal' } },
        { data: { id: 'e2', source: 'n3', target: 'n1', type: 'c2-channel' } }
      ]
    };
    return DashboardGraphSchema.parse(data);
  }
};
