import { describe, it, expect } from 'vitest';
import { auditService } from '../mock/audit.service';

describe('mock auditService', () => {
  it('getLogs returns paged logs', async () => {
    const r = await auditService.getLogs({ page: 1, pageSize: 10 });
    expect(r).toHaveProperty('total');
    expect(Array.isArray(r.data)).toBe(true);
    expect(r.data.length).toBeGreaterThan(0);
  });

  it('searchLogs returns results for query', async () => {
    const r = await auditService.searchLogs('test-query');
    expect(r).toHaveProperty('total');
    expect(Array.isArray(r.data)).toBe(true);
  });
});
