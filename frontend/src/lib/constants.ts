export const STRINGS = {
  APP_NAME: 'BankSentinel',
  SUBTITLE: 'Security Operations Center',
  ERRORS: {
    INVALID_CREDENTIALS: 'Invalid credentials',
    SERVICE_UNAVAILABLE: 'Service unavailable'
  }
} as const;

export const PERMISSIONS = {
  TRIGGER_CONTAINMENT: 'trigger:containment',
  VIEW_BEHAVIORAL_DATA: 'view:behavioral'
} as const;

export const enum ROLE {
  SOC_ANALYST = 'SOC_ANALYST',
  COMPLIANCE_OFFICER = 'COMPLIANCE_OFFICER',
  ADMIN = 'ADMIN'
}
