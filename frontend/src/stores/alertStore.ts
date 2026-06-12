import { create } from 'zustand';
import type { Alert } from '@types/alert.types';

interface AlertStore {
  alerts: Alert[];
  addAlert: (alert: Alert) => void;
  clearAlerts: () => void;
}

export const useAlertStore = create<AlertStore>((set) => ({
  alerts: [],
  addAlert: (alert) => set((state) => ({
    // Prepend new alerts so they appear at the top
    alerts: [alert, ...state.alerts],
  })),
  clearAlerts: () => set({ alerts: [] }),
}));
