const useMock = import.meta.env.VITE_USE_MOCK_API === 'true';

type AuthService = typeof import('./mock/auth.service').authService;

let impl: { authService: AuthService };
if (useMock) impl = await import('./mock/auth.service');
else impl = await import('./real/auth.service');

export const authService = impl.authService;
