import React from 'react';
import { Outlet } from 'react-router-dom';
import { useUIStore } from '@stores/ui.store';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

export const AppShell: React.FC = () => {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 overflow-y-auto bg-background-primary">
        <TopBar />
        <div className="p-4">
          <Outlet />
        </div>
      </main>
    </div>
  );
};
