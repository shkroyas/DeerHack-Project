import React from 'react';
import { STRINGS } from '@lib/constants';
import { LoginForm } from './LoginForm';
import { Shield } from 'lucide-react';

const LoginPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#0a0a0c] flex items-center justify-center relative overflow-hidden">
      {/* Background glowing blobs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/10 rounded-full blur-[120px]" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-teal-500/10 rounded-full blur-[120px]" />

      <div className="relative z-10 w-full max-w-md p-8 bg-black/40 backdrop-blur-xl border border-white/5 rounded-2xl shadow-2xl animate-fade-up">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-lg shadow-emerald-500/20 mb-6">
            <Shield size={32} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight mb-2">
            {STRINGS.APP_NAME}
          </h1>
          <p className="text-sm text-slate-400 text-center px-4">
            {STRINGS.SUBTITLE}
          </p>
        </div>

        <LoginForm />

        <div className="mt-8 pt-6 border-t border-white/5 text-center">
          <p className="text-xs text-slate-500">
            Protected by Advanced AI Threat Detection
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
