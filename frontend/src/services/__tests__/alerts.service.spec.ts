import { describe, it, expect } from 'vitest';
import { alertsService } from '../mock/alerts.service';

describe('mock alertsService', () => {
  it('getAlerts returns list with total and data', async () => {
    const res = await alertsService.getAlerts({});
    expect(res).toHaveProperty('total');
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data.length).toBeGreaterThan(0);
  });

  it('getAlertById returns a specific alert', async () => {
    const list = await alertsService.getAlerts({});
    const id = list.data[0].id;
    const a = await alertsService.getAlertById(id);
    expect(a.id).toBe(id);
  });

  it('patchAck returns the updated alert', async () => {
    const list = await alertsService.getAlerts({});
    const id = list.data[0].id;
    const a = await alertsService.patchAck(id);
    expect(a.id).toBe(id);
  });

  it('bulkAck returns updated count', async () => {
    const list = await alertsService.getAlerts({});
    const ids = list.data.slice(0, 3).map((x) => x.id);
    const res = await alertsService.bulkAck(ids);
    expect(res).toHaveProperty('updated');
    expect(res.updated).toBeGreaterThanOrEqual(0);
  });
});
