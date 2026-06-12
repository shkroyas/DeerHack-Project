import { describe, it, expect } from 'vitest';
import { responseService } from '../mock/response.service';

describe('mock responseService', () => {
  it('quarantine returns action result', async () => {
    const res = await responseService.quarantine('ALERT-1', 'test reason');
    expect(res).toHaveProperty('actionId');
  });

  it('blockIp returns action result', async () => {
    const res = await responseService.blockIp('ALERT-1', 'test reason');
    expect(res).toHaveProperty('result');
  });
});
