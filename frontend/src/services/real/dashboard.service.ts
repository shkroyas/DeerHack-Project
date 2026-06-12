import { apiClient } from '@lib/axios';
import { DashboardGraphSchema, DashboardKpiSchema } from '@types/dashboard.types';

export const dashboardService = {
  getKpis: async () => {
    const res = await apiClient.get('/dashboard/kpis');
    return DashboardKpiSchema.parse({
      threatsToday: res.data.threats_today,
      falsePositiveRate: res.data.false_positive_rate,
      intelFeedAgeMin: res.data.intel_feed_age_min ?? 0,
      meanResponseTimeMin: res.data.mean_response_time_min,
    });
  },
  getGraph: async () => {
    const res = await apiClient.get('/dashboard/graph');
    return DashboardGraphSchema.parse(res.data);
  }
};
