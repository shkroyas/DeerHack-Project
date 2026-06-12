import React, { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

export const AlertFeed: React.FC = () => {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const queryClient = useQueryClient();

  useEffect(() => {
    // Determine WS URL based on current origin or API base
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const baseUrl = import.meta.env.VITE_API_BASE_URL 
      ? import.meta.env.VITE_API_BASE_URL.replace(/^https?:\/\//, '')
      : '127.0.0.1:8000';
    
    const ws = new WebSocket(`${protocol}//${baseUrl}/ws/alerts`);

    ws.onopen = () => {
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'alert' && msg.data) {
          setAlerts((prev) => [msg.data, ...prev].slice(0, 50)); // Keep last 50
          
          // Invalidate KPIs and graph so they refresh immediately
          queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        }
      } catch (e) {
        console.error('Failed to parse WS message', e);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
    };

    return () => {
      ws.close();
    };
  }, [queryClient]);

  const severityColor: Record<string, string> = {
    CRITICAL: 'severity-critical',
    HIGH: 'severity-high',
    MEDIUM: 'severity-medium',
    LOW: 'severity-low',
    INFO: 'text-text-muted',
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 mb-3 px-1">
        <span className={isConnected ? "status-dot-online" : "status-dot-offline"} />
        <span className="text-[10px] text-text-muted uppercase tracking-wider">
          {isConnected ? "Connected to Live Stream" : "Reconnecting..."}
        </span>
      </div>

      <div className="space-y-2 flex-1 overflow-y-auto min-h-0 pr-1">
        {alerts.length === 0 && (
          <div className="text-center py-8">
            <div className="text-text-muted text-xs">Waiting for live traffic...</div>
          </div>
        )}
        {alerts.map((alert: any, i: number) => {
          const priority = alert.priority || 'INFO';
          const crs = alert.crs || 0;
          return (
            <div
              key={alert.id || i}
              className={`p-3 rounded-lg bg-background-elevated border border-background-border animate-fade-up hover:border-background-border/80 transition-colors cursor-pointer`}
              style={{ animationDelay: `${Math.min(i * 50, 200)}ms` }}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold ${severityColor[priority]}`}>
                    {priority}
                  </span>
                  <span className="text-[10px] text-text-muted font-mono">
                    CRS: {crs.toFixed(3)}
                  </span>
                </div>
                <span className="text-[10px] text-text-muted">
                  {alert.agents_fired?.join('+') || '—'}
                </span>
              </div>
              <div className="text-xs text-text-primary truncate">
                {alert.src_ip || '—'} → {alert.dst_ip || '—'}
              </div>
              {alert.is_suppressed && (
                <div className="text-[10px] text-text-muted mt-1 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 bg-text-muted rounded-full" />
                  Suppressed: {alert.suppression_reason}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
