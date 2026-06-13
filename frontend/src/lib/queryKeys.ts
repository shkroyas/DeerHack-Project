import type { AlertFilters } from '@/types/alert.types';

export const queryKeys = {
  alerts: {
    all: ['alerts'] as const,
    filtered: (filters: AlertFilters) => ['alerts', filters] as const,
    detail: (id: string) => ['alerts', 'detail', id] as const
  },
  incidents: {
    all: ['incidents'] as const,
    detail: (id: string) => ['incidents', 'detail', id] as const,
    graph: (id: string) => ['incidents', 'graph', id] as const
  },
  agents: {
    health: ['agents', 'health'] as const
  },
  dashboard: {
    kpis: ['dashboard', 'kpis'] as const,
    graph: ['dashboard', 'graph'] as const
  }
} as const;
