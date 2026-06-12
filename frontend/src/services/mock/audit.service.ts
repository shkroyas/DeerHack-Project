import { AuditListSchema } from '@types/audit.types';

export const auditService = {
  getLogs: async ({ page = 1, pageSize = 50 } = {}) => {
    await new Promise((r) => setTimeout(r, 200));
    const total = 500;
    const items = Array.from({ length: Math.min(pageSize, total - (page - 1) * pageSize) }).map((_, i) => ({
      id: `LOG-${(page - 1) * pageSize + i + 1}`,
      ts: new Date(Date.now() - (i * 60000)).toISOString(),
      user: i % 3 === 0 ? 'system' : 'analyst@example.com',
      action: ['LOGIN', 'ALERT_ACK', 'INCIDENT_CREATE', 'EXPORT'][i % 4],
      details: { ip: `192.0.2.${i % 255}`, agentId: `AG-${100 + i}` }
    }));
    return AuditListSchema.parse({ total, page, data: items });
  },
  searchLogs: async (q: string) => {
    await new Promise((r) => setTimeout(r, 150));
    return AuditListSchema.parse({ total: 1, data: [{ id: 'LOG-1', ts: new Date().toISOString(), user: 'analyst@example.com', action: 'SEARCH', details: { query: q } }] });
  }
};
