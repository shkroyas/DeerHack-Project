export const getConfig = () => {
  const env = import.meta.env;
  const required = [
    'VITE_API_BASE_URL',
    'VITE_WS_URL',
    'VITE_USE_MOCK_API',
    'VITE_APP_VERSION',
    'VITE_ENVIRONMENT'
  ];

  for (const key of required) {
    if (!env[key]) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
  }

  return {
    apiBaseUrl: env.VITE_API_BASE_URL as string,
    wsUrl: env.VITE_WS_URL as string,
    useMockApi: (env.VITE_USE_MOCK_API === 'true'),
    appVersion: env.VITE_APP_VERSION as string,
    environment: env.VITE_ENVIRONMENT as string
  };
};

export type AppConfig = ReturnType<typeof getConfig>;
