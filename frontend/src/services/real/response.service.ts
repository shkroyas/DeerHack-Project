import { apiClient } from '@lib/axios';
import { ActionResultSchema } from '@types/response.types';

export const responseService = {
  quarantine: async (alertId: string, reason: string) => {
    const res = await apiClient.post(`/respond/${alertId}/quarantine`, { reason });
    return ActionResultSchema.parse(res.data);
  },
  suspendAccount: async (alertId: string, reason: string) => {
    const res = await apiClient.post(`/respond/${alertId}/suspend-account`, { reason });
    return ActionResultSchema.parse(res.data);
  },
  blockIp: async (alertId: string, reason: string) => {
    const res = await apiClient.post(`/respond/${alertId}/block-ip`, { reason });
    return ActionResultSchema.parse(res.data);
  },
  snapshot: async (alertId: string, reason: string) => {
    const res = await apiClient.post(`/respond/${alertId}/snapshot`, { reason });
    return ActionResultSchema.parse(res.data);
  }
};
