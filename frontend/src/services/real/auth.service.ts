import { apiClient } from '@lib/axios';
import { z } from 'zod';
import { UserSchema } from '@types/auth.types';

const LoginSchema = z.object({ accessToken: z.string(), user: UserSchema });

export const authService = {
  login: async (email: string, password: string) => {
    // Demo bypass since backend has no auth yet
    if (email === 'admin@example.com' && password.length >= 8) {
      const resp = { accessToken: 'mock.access.token', user: { id: 'u-1', email, name: 'Admin User', role: 'ADMIN' } };
      return LoginSchema.parse(resp);
    }
    throw new Error('Invalid credentials');
  },
  refresh: async () => {
    return z.object({ accessToken: z.string() }).parse({ accessToken: 'mock.access.token' });
  },
  logout: async () => {
    return true;
  }
};
