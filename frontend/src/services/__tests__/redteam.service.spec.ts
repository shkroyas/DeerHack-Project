import { describe, it, expect } from 'vitest';
import { redteamService } from '../mock/redteam.service';

describe('mock redteamService', () => {
  it('getScenarios returns scenarios', async () => {
    const res = await redteamService.getScenarios();
    expect(res.length).toBeGreaterThan(0);
  });

  it('launch returns runId', async () => {
    const res = await redteamService.launch('swift_c2');
    expect(res.runId).toBeTruthy();
  });

  it('getResult returns result', async () => {
    const res = await redteamService.getResult('RUN-1');
    expect(res).toHaveProperty('detected');
  });
});
