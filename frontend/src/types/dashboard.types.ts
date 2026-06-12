import { z } from 'zod';
import { GraphSchema } from './graph.types';

export const DashboardKpiSchema = z.object({
  threatsToday: z.number(),
  falsePositiveRate: z.number(),
  intelFeedAgeMin: z.number(),
  meanResponseTimeMin: z.number()
});

export const DashboardGraphSchema = GraphSchema;

export type DashboardKpis = z.infer<typeof DashboardKpiSchema>;
export type DashboardGraph = z.infer<typeof DashboardGraphSchema>;
