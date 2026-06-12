import { AgentStatusSchema } from '@types/agent.types';

const agents = [
  { id: 'packet', name: 'Packet Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 120 },
  { id: 'flow', name: 'Flow Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 80 },
  { id: 'behavior', name: 'Behavior Agent', status: 'DEGRADED', lastHeartbeat: new Date().toISOString(), eps: 30 },
  { id: 'correlation', name: 'Correlation Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 200 },
  { id: 'response', name: 'Response Agent', status: 'ONLINE', lastHeartbeat: new Date().toISOString(), eps: 5 }
];

export const agentsService = {
  getHealth: async () => {
    await new Promise((r) => setTimeout(r, 200));
    return agents.map((a) => AgentStatusSchema.parse(a));
  }
};
