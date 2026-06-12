import { ActionResultSchema } from '@types/response.types';

const makeResult = () => ActionResultSchema.parse({
  actionId: `ACT-${Math.floor(Math.random() * 9000) + 1000}`,
  result: 'SUCCESS'
});

export const responseService = {
  quarantine: async (alertId: string, reason: string) => {
    await new Promise((r) => setTimeout(r, 300));
    return makeResult();
  },
  suspendAccount: async (alertId: string, reason: string) => {
    await new Promise((r) => setTimeout(r, 400));
    return makeResult();
  },
  blockIp: async (alertId: string, reason: string) => {
    await new Promise((r) => setTimeout(r, 200));
    return makeResult();
  },
  snapshot: async (alertId: string, reason: string) => {
    await new Promise((r) => setTimeout(r, 500));
    return makeResult();
  }
};
