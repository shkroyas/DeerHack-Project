import axios from 'axios';
import axiosRetry from 'axios-retry';
import { getConfig } from './config';
import { toast } from 'react-hot-toast';
import { STRINGS } from './constants';
import { useAuthStore } from '@stores/auth.store';

const config = getConfig();

export const apiClient = axios.create({
  baseURL: config.apiBaseUrl,
  withCredentials: false
});

axiosRetry(apiClient, {
  retries: 2, retryCondition: (error) => {
    return (error.response?.status || 0) >= 500;
  }
});

apiClient.interceptors.request.use((req) => {
  const { accessToken, user } = useAuthStore.getState();
  req.headers = req.headers ?? {};
  req.headers['X-Client-Version'] = config.appVersion;
  req.headers['X-Request-Id'] = String(Math.random()).slice(2, 12);

  if (accessToken) {
    req.headers.Authorization = `Bearer ${accessToken}`;
  }

  const method = (req.method ?? 'get').toLowerCase();
  if (method !== 'get' && user) {
    req.headers['X-User-ID'] = user.id;
    req.headers['X-User-Role'] = user.role;
  }

  return req;
});

apiClient.interceptors.response.use(
  (res) => res,
  async (error) => {
    const status = error?.response?.status;
    if (status === 401) {
      // Let useAuth handle refresh flow — just normalize error here
      toast.error(STRINGS.ERRORS.INVALID_CREDENTIALS);
    } else {
      toast.error(STRINGS.ERRORS.SERVICE_UNAVAILABLE);
    }
    return Promise.reject(error);
  }
);
