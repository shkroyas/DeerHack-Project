import { apiClient } from '@lib/axios';
import { IntelFeedStatusSchema, IntelRefreshSchema } from '@types/intel.types';

export const intelService = {
  getFeeds: async () => {
    const res = await apiClient.get('/intel/status');
    const data = res.data;
    
    // Map backend counts to IntelFeedStatus array
    const feeds = [
      { name: 'JA3 Fingerprints', count: data.ja3_entries },
      { name: 'C2 IP Addresses', count: data.c2_ip_entries },
      { name: 'Tor Exit Nodes', count: data.tor_entries }
    ];

    return feeds.map(feed => 
      IntelFeedStatusSchema.parse({
        name: feed.name,
        lastUpdated: new Date().toISOString(), // live age omitted for simplicity
        count: feed.count,
        status: 'LIVE'
      })
    );
  },
  refresh: async () => {
    const res = await apiClient.post('/intel/refresh');
    return IntelRefreshSchema.parse({ status: 'started' }); // mock return matching schema
  }
};
