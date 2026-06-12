import { IntelFeedStatusSchema, IntelRefreshSchema } from '@types/intel.types';

export const intelService = {
  getFeeds: async () => {
    await new Promise((r) => setTimeout(r, 150));
    const data = [
      { name: 'abuse.ch JA3', lastUpdated: new Date().toISOString(), count: 12345, status: 'LIVE' },
      { name: 'Feodo Tracker', lastUpdated: new Date().toISOString(), count: 234, status: 'LIVE' }
    ];
    return data.map((item) => IntelFeedStatusSchema.parse(item));
  },
  refresh: async () => {
    await new Promise((r) => setTimeout(r, 300));
    return IntelRefreshSchema.parse({ status: 'started' });
  }
};
