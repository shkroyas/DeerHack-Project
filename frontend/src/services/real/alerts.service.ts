import { apiClient } from '@lib/axios';
import { AlertSchema, AlertListSchema } from '@types/alert.types';
import type { AlertFilters } from '@types/alert.types';

export const alertsService = {
  getAlerts: async (filters: AlertFilters) => {
    // We hit the live demo pipeline to generate alerts since we don't have an alerts DB
    const response = await apiClient.post('/pipeline/apt-demo', {}, { timeout: 60000 });
    
    const mappedAlerts = response.data.map((item: any) => {
      const corr = item.correlation_result;
      const pkt = item.packet_alert;
      const flow = item.flow_alert;
      
      return AlertSchema.parse({
        id: `ALERT-${corr.record_id}`,
        timestamp: new Date().toISOString(),
        sourceIp: corr.src_ip || (pkt && pkt.src_ip) || (flow && flow.src_ip) || "Unknown",
        destinationIp: corr.dst_ip || (pkt && pkt.dst_ip) || (flow && flow.dst_ip) || "Unknown",
        severity: corr.priority || "LOW",
        mitre: item.behavior_alert?.scenario_hint || "T1071.001",
        agents: corr.agents_fired || [],
        crs: corr.crs || 0.0,
        challenge: 'C3' // correlation challenge
      });
    });

    return AlertListSchema.parse({
      data: mappedAlerts,
      total: mappedAlerts.length,
      page: 1
    });
  },
  getAlertById: async (id: string) => {
    // Since we don't have persistence, we return a dummy when detailed view is requested
    return AlertSchema.parse({
        id: id,
        timestamp: new Date().toISOString(),
        sourceIp: "10.0.0.1",
        destinationIp: "192.168.1.1",
        severity: "HIGH",
        mitre: "T1071",
        agents: ["packet", "flow"],
        crs: 0.85,
        challenge: "C3"
    });
  }
};
