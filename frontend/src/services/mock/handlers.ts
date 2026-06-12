import { rest } from 'msw';
import { getConfig } from '@lib/config';

const cfg = getConfig();

const mockAlerts = Array.from({ length: 50 }).map((_, i) => ({
  id: `ALERT-${1000 + i}`,
  timestamp: new Date(Date.now() - i * 60000).toISOString(),
  sourceIp: `203.0.113.${(i % 240) + 1}`,
  destinationIp: `10.0.0.${(i % 240) + 1}`,
  severity: ['CRITICAL','HIGH','MEDIUM','LOW','QUEUED'][i % 5],
  mitre: ['T1071.001','T1046','T1213','T1021'][i % 4],
  agents: ['Packet','Flow'][i % 2 === 0 ? 0 : 1],
  crs: Math.round(Math.random() * 100) / 100,
  challenge: ['C1','C2','C3','C4'][i % 4]
}));

const mockAgents = [
  { id: 'packet', name: 'Packet Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 120 },
  { id: 'flow', name: 'Flow Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 80 },
  { id: 'behavior', name: 'Behavior Agent', status: 'DEGRADED', lastHeartbeat: new Date().toISOString(), eps: 30 },
  { id: 'correlation', name: 'Correlation Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 200 },
  { id: 'response', name: 'Response Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 5 }
];

export const handlers = [
  rest.get(`${cfg.apiBaseUrl}/alerts`, (req, res, ctx) => {
    return res(ctx.status(200), ctx.json({ data: mockAlerts.slice(0, 50), total: mockAlerts.length, page: 1 }));
  }),
  rest.get(`${cfg.apiBaseUrl}/agents/health`, (req, res, ctx) => {
    return res(ctx.status(200), ctx.json(mockAgents));
  }),
  rest.get(`${cfg.apiBaseUrl}/dashboard/kpis`, (req, res, ctx) => {
    return res(ctx.status(200), ctx.json({ threatsToday: 123, falsePositiveRate: 7.1, intelFeedAgeMin: 12, meanResponseTimeMin: 4.2 }));
  }),
  rest.get(`${cfg.apiBaseUrl}/dashboard/graph`, (req, res, ctx) => {
    return res(ctx.status(200), ctx.json({ nodes: [ { data: { id: 'n1', label: 'WS-1', type: 'WORKSTATION', ip: '10.0.1.12', state: 'safe' } } ], edges: [] }));
  })
];
