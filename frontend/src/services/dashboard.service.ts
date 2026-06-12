const useMock = import.meta.env.VITE_USE_MOCK_API === 'true';

type DashboardService = typeof import('./mock/dashboard.service').dashboardService;

let impl: { dashboardService: DashboardService };
if (useMock) impl = await import('./mock/dashboard.service');
else impl = await import('./real/dashboard.service');

export const dashboardService = impl.dashboardService;
