import { z } from 'zod';

export const GraphNodeSchema = z.object({
  data: z.object({
    id: z.string(),
    label: z.string(),
    type: z.string(),
    ip: z.string().optional(),
    state: z.string().optional()
  })
});

export const GraphEdgeSchema = z.object({
  data: z.object({
    id: z.string(),
    source: z.string(),
    target: z.string(),
    type: z.string().optional(),
    label: z.string().optional()
  })
});

export const GraphSchema = z.object({
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema)
});

export type GraphNode = z.infer<typeof GraphNodeSchema>;
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;
export type GraphData = z.infer<typeof GraphSchema>;
