import React from 'react';
import { STRINGS } from '@lib/constants';
import { LoginForm } from './LoginForm';

const LoginPage: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-full max-w-md p-6 bg-panel rounded">
        <img src="/banksentinel-logo.svg" alt="BankSentinel" className="mx-auto mb-4" />
        <h1 className="text-xl text-text.primary text-center">{STRINGS.APP_NAME}</h1>
        <p className="text-sm text-text.secondary text-center">{STRINGS.SUBTITLE}</p>
        <div className="mt-6">
          <LoginForm />
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
