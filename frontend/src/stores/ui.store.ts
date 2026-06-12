import create from 'zustand';
import { persist } from 'zustand/middleware';

interface UIState {
  sidebarCollapsed: boolean;
  activeTheme: 'dark' | 'light';
  toggleSidebar: () => void;
  setTheme: (t: UIState['activeTheme']) => void;
}

export const useUIStore = create(persist<UIState>((set) => ({
  sidebarCollapsed: false,
  activeTheme: 'dark',
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setTheme: (t) => set({ activeTheme: t })
}), { name: 'banksentinel-ui' }));
