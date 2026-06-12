import { Config } from 'tailwindcss';

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: {
          primary: '#06080f',
          secondary: '#0c0e17',
          panel: '#111422',
          elevated: '#181c2e',
          border: '#1f2337'
        },
        text: {
          primary: '#E8EAF6',
          secondary: '#9BA4C4',
          muted: '#5C6480'
        },
        challenge: {
          c1: '#14B8A6',
          c2: '#F59E0B',
          c3: '#8B5CF6',
          c4: '#3B82F6'
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#22C55E',
          info: '#6B7280'
        },
        state: {
          safe: '#374151',
          suspicious: '#B45309',
          compromised: '#991B1B',
          isolated: '#1E293B'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      },
      animation: {
        'fade-up': 'fade-up 0.4s ease-out both',
        'slide-right': 'slide-in-right 0.3s ease-out both',
        'slide-left': 'slide-in-left 0.3s ease-out both',
        'scale-in': 'scale-in 0.3s ease-out both',
        'count-up': 'count-up 0.5s ease-out both',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'threat-pulse': 'threat-pulse 1.5s ease-in-out infinite',
        'shimmer': 'shimmer 1.5s ease-in-out infinite',
      },
      backdropBlur: {
        xs: '2px',
      },
      boxShadow: {
        'glow-blue': '0 0 20px rgba(59, 130, 246, 0.15)',
        'glow-purple': '0 0 20px rgba(139, 92, 246, 0.15)',
        'glow-teal': '0 0 20px rgba(20, 184, 166, 0.15)',
        'glow-amber': '0 0 20px rgba(245, 158, 11, 0.15)',
        'glow-red': '0 0 20px rgba(239, 68, 68, 0.2)',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(ellipse at center, var(--tw-gradient-stops))',
        'grid-pattern': 'linear-gradient(rgba(31,35,55,0.3) 1px, transparent 1px), linear-gradient(to right, rgba(31,35,55,0.3) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
    }
  },
  plugins: []
};

export default config;
