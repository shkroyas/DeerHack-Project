import { describe, it, expect } from 'vitest';
import { intelService } from '../mock/intel.service';

describe('mock intelService', () => {
  it('getFeeds returns feed list', async () => {
    const res = await intelService.getFeeds();
    expect(Array.isArray(res)).toBe(true);
    expect(res.length).toBeGreaterThan(0);
  });

  it('refresh returns started status', async () => {
    const res = await intelService.refresh();
    expect(res.status).toBe('started');
  });
});
