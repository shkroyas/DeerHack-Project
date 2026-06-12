const useMock = import.meta.env.VITE_USE_MOCK_API === 'true';

type ResponseService = typeof import('./mock/response.service').responseService;

let impl: { responseService: ResponseService };
if (useMock) impl = await import('./mock/response.service');
else impl = await import('./real/response.service');

export const responseService = impl.responseService;
