const useMock = import.meta.env.VITE_USE_MOCK_API === 'true';

type AuditService = typeof import('./mock/audit.service').auditService;

let impl: { auditService: AuditService };
if (useMock) impl = await import('./mock/audit.service');
else impl = await import('./real/audit.service');

export const auditService = impl.auditService;
