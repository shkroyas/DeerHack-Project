import { z } from 'zod';
import { UserSchema } from '@types/auth.types';

const LoginSchema = z.object({ accessToken: z.string(), user: UserSchema });

export const authService = {
  login: async (email: string, password: string) => {
    await new Promise((r) => setTimeout(r, 300));
    if (email === 'admin@example.com' && password.length >= 8) {
      const resp = { accessToken: 'mock.access.token', user: { id: 'u-1', email, name: 'Admin User', role: 'ADMIN' } };
      return LoginSchema.parse(resp);
    }
    throw new Error('Invalid credentials');
  },
  refresh: async () => {
    await new Promise((r) => setTimeout(r, 200));
    return { accessToken: 'mock.access.token' };
  },
  logout: async () => {
    await new Promise((r) => setTimeout(r, 100));
    return true;
  }
};
