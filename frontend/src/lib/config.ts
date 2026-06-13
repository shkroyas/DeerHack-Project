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

  let apiBaseUrl = env.VITE_API_BASE_URL as string;
  let wsUrl = env.VITE_WS_URL as string;
  
  if (apiBaseUrl && (apiBaseUrl.includes('localhost') || apiBaseUrl.includes('127.0.0.1'))) {
      apiBaseUrl = `http://${window.location.hostname}:8000`;
  }
  
  if (wsUrl && (wsUrl.includes('localhost') || wsUrl.includes('127.0.0.1'))) {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      wsUrl = `${protocol}//${window.location.hostname}:8000`;
  }

  return {
    apiBaseUrl,
    wsUrl,
    useMockApi: (env.VITE_USE_MOCK_API === 'true'),
    appVersion: env.VITE_APP_VERSION as string,
    environment: env.VITE_ENVIRONMENT as string
  };
};

export type AppConfig = ReturnType<typeof getConfig>;
