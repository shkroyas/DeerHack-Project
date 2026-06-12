const useMock = import.meta.env.VITE_USE_MOCK_API === 'true';

type AlertsService = typeof import('./mock/alerts.service').alertsService;

let impl: { alertsService: AlertsService };
if (useMock) {
    impl = await import('./mock/alerts.service');
} else {
    impl = await import('./real/alerts.service');
}

export const alertsService = impl.alertsService;
