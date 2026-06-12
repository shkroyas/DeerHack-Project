const useMock = import.meta.env.VITE_USE_MOCK_API === 'true';

type IntelService = typeof import('./mock/intel.service').intelService;

let impl: { intelService: IntelService };
if (useMock) impl = await import('./mock/intel.service');
else impl = await import('./real/intel.service');

export const intelService = impl.intelService;
