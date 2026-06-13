import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { agentsService } from '@services/agents.service';
import { Settings, Shield, Server, Download } from 'lucide-react';
import { queryKeys } from '@lib/queryKeys';

const SettingsPage: React.FC = () => {
  const [liveMode, setLiveMode] = useState(true);

  useEffect(() => {
    fetch(`http://${window.location.hostname}:8000/pipeline/mode`)
      .then(res => res.json())
      .then(data => setLiveMode(data.mode === 'live'))
      .catch(console.error);
  }, []);

  const toggleLiveMode = () => {
    const newMode = !liveMode;
    setLiveMode(newMode);
    fetch(`http://${window.location.hostname}:8000/pipeline/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: newMode ? 'live' : 'simulated' })
    }).catch(console.error);
  };

  const { data: agents } = useQuery({
    queryKey: queryKeys.agents.health,
    queryFn: agentsService.getHealth,
  });

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6 animate-fade-up">
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-lg bg-background-elevated border border-background-border flex items-center justify-center">
          <Settings size={20} className="text-text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">System Settings</h1>
          <p className="text-sm text-text-muted">Configure BankSentinel IDS pipeline and integrations</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col */}
        <div className="col-span-2 space-y-6">
          
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Server size={16} /> Pipeline Configuration
            </h2>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded bg-background-primary/50 border border-background-border">
                <div>
                  <div className="text-sm font-medium text-white">Live Mode</div>
                  <div className="text-xs text-text-muted">Use real backend services instead of mock data</div>
                </div>
                <div 
                  className={`w-10 h-6 rounded-full relative cursor-pointer ${liveMode ? 'bg-challenge-c4' : 'bg-background-darker'}`}
                  onClick={toggleLiveMode}
                >
                  <div className={`w-4 h-4 bg-white rounded-full absolute top-1 transition-all duration-300 ${liveMode ? 'right-1' : 'left-1'}`} />
                </div>
              </div>
              <div className="flex items-center justify-between p-3 rounded bg-background-primary/50 border border-background-border">
                <div>
                  <div className="text-sm font-medium text-white">Context-Aware Routing (C2)</div>
                  <div className="text-xs text-text-muted">Enable calendar-aware FPR reduction models</div>
                </div>
                <div className="w-10 h-6 bg-challenge-c4 rounded-full relative cursor-pointer">
                  <div className="w-4 h-4 bg-white rounded-full absolute right-1 top-1" />
                </div>
              </div>
              <div className="flex items-center justify-between p-3 rounded bg-background-primary/50 border border-background-border">
                <div>
                  <div className="text-sm font-medium text-white">Automated Containment</div>
                  <div className="text-xs text-text-muted">Trigger Response Agent when CRS &ge; 0.85</div>
                </div>
                <div className="w-10 h-6 bg-challenge-c4 rounded-full relative cursor-pointer">
                  <div className="w-4 h-4 bg-white rounded-full absolute right-1 top-1" />
                </div>
              </div>
            </div>
          </div>

          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Shield size={16} /> Threat Intelligence
            </h2>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label htmlFor="nrbNode" className="block text-xs font-semibold text-text-muted uppercase mb-1.5">NRB Node ID</label>
                  <input id="nrbNode" type="text" className="input-field w-full font-mono text-xs opacity-50" defaultValue="NRB-FED-012" disabled />
                </div>
                <div>
                  <label htmlFor="c2list" className="block text-xs font-semibold text-text-muted uppercase mb-1.5">C2 IP Blocklist</label>
                  <input id="c2list" type="text" className="input-dark w-full" defaultValue="https://feodotracker.abuse.ch/downloads/ipblocklist.csv" />
                </div>
              </div>
              <div>
                <label htmlFor="sync" className="block text-xs font-semibold text-text-muted uppercase mb-1.5">Sync Interval (Minutes)</label>
                <input id="sync" type="number" className="input-dark w-full" defaultValue={30} />
              </div>
            </div>
          </div>
        </div>

        {/* Right Col */}
        <div className="col-span-1 space-y-6">
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-white mb-4">Agent Status</h2>
            <div className="space-y-3">
              {(agents ?? []).map((agent: Record<string, unknown>) => (
                <div key={agent.id as string} className="flex items-center justify-between">
                  <span className="text-xs text-text-secondary">{agent.name as string}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-text-muted font-mono">{(agent.eps as number) || 0} EPS</span>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" className="sr-only peer" defaultChecked={(agent.status as string) === 'ONLINE'} />
                      <div className="w-9 h-5 bg-background-border peer-checked:bg-success rounded-full peer" />
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Download size={16} /> Data Export
            </h2>
            <div className="space-y-2">
              <button className="w-full btn-ghost py-2">Export Audit Logs (CSV)</button>
              <button className="w-full btn-ghost py-2">Download NRB Compliance Report</button>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default SettingsPage;
