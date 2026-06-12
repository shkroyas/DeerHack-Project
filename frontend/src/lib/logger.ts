export const logger = {
  debug: (...args: unknown[]) => {
    // Only log debug in non-production
    if (import.meta.env.VITE_ENVIRONMENT !== 'production') {
      // eslint-disable-next-line no-console
      console.debug('[banksentinel][debug]', ...args);
    }
  },
  info: (...args: unknown[]) => {
    // eslint-disable-next-line no-console
    console.info('[banksentinel][info]', ...args);
  },
  error: (...args: unknown[]) => {
    // eslint-disable-next-line no-console
    console.error('[banksentinel][error]', ...args);
  }
};
