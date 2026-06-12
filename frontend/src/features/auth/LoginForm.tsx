import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuth } from '@hooks/useAuth';

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
});

type FormValues = z.infer<typeof schema>;

export const LoginForm: React.FC = () => {
  const { login } = useAuth();
  const { register, handleSubmit, formState } = useForm<FormValues>({ resolver: zodResolver(schema) });

  const onSubmit = async (data: FormValues) => {
    await login(data.email, data.password);
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <div>
        <label className="block text-sm text-text.secondary">Email</label>
        <input {...register('email')} className="w-full mt-1 p-2 rounded bg-panel text-text.primary" />
        {formState.errors.email && <div className="text-xs text-severity-critical mt-1">Invalid email</div>}
      </div>
      <div>
        <label className="block text-sm text-text.secondary">Password</label>
        <input type="password" {...register('password')} className="w-full mt-1 p-2 rounded bg-panel text-text.primary" />
        {formState.errors.password && <div className="text-xs text-severity-critical mt-1">Min 8 characters</div>}
      </div>
      <button type="submit" className="px-4 py-2 bg-challenge-c3 text-white rounded">Sign in</button>
    </form>
  );
};
