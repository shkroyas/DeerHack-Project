import { apiClient } from '@lib/axios';

export const auditService = {
  getLogs: async (filters: { page?: number; pageSize?: number } = {}) => {
    const res = await apiClient.get('/audit/logs', { params: { limit: filters.pageSize || 50 } });
    
    // res.data is an array of AuditLogEntry
    const mappedLogs = res.data.map((log: any, i: number) => ({
      id: i.toString(),
      timestamp: log.timestamp,
      actor: "BankSentinel IDS",
      action: log.action,
      resource: "ResponseAgent",
      status: log.status,
      details: "",
      ipAddress: "127.0.0.1",
      hash: log.hash
    }));

    return {
      data: mappedLogs,
      total: mappedLogs.length,
      page: filters.page || 1
    };
  },
  searchLogs: async (q: string) => {
    return auditService.getLogs();
  }
};
