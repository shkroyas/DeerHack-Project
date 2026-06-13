import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { AgentHealthPanel } from '@components/feature/AgentHealthPanel';
import { ModelPipeline } from '@components/feature/ModelPipeline';
import { AlertFeed } from '@components/feature/AlertFeed';
import { EncryptedTrafficPanel } from '@components/feature/EncryptedTrafficPanel';
import { RegimeContextBadge } from '@components/feature/RegimeContextBadge';
import { MITRENavigator } from '@components/feature/MITRENavigator';
import { SHAPExplanation } from '@components/feature/SHAPExplanation';
import { AuditChainViewer } from '@components/feature/AuditChainViewer';
import { CRSDistribution } from '@components/common/CRSDistribution';
import { auditService } from '@services/audit.service';
import { dashboardService } from '@services/dashboard.service';

const DashboardPage: React.FC = () => {
  const { data: auditData } = useQuery({ 
    queryKey: ['audit', 'logs'], 
    queryFn: () => auditService.getLogs({ page: 1, pageSize: 5 }),
    refetchInterval: 5000 
  });

  const { data: kpiData } = useQuery({
    queryKey: ['dashboard', 'kpis'],
    queryFn: dashboardService.getKpis,
    refetchInterval: 5000,
  });

  return (
    <div className="space-y-4 p-2 animate-fade-up h-full overflow-y-auto">
      {/* Agent Health Strip */}
      <AgentHealthPanel />

      <div className="flex items-end justify-between gap-3 px-1">
        <div>
          <h1 className="text-lg font-bold text-white">SOC Dashboard</h1>
          <p className="text-xs text-text-muted">Live detection, triage, and evidence tracking in one view.</p>
        </div>
        <div className="hidden md:block text-[10px] uppercase tracking-[0.18em] text-text-muted">
          Balanced operational overview
        </div>
      </div>

      {/* Main Grid: balanced operations layout */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 xl:items-start">
        {/* LEFT: Attack Graph + context cards */}
        <div className="xl:col-span-7 flex flex-col gap-4 self-start">
          <div className="glass-panel p-4 overflow-x-auto">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Network Threat Topology</h2>
              <span className="challenge-badge challenge-badge-c1">Pipeline</span>
            </div>
            <ModelPipeline />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="glass-panel p-4 h-full">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Risk Score Distribution</span>
                <span className="challenge-badge challenge-badge-c3">C3</span>
              </div>
              <CRSDistribution
                data={[
                  { label: '0-0.2', value: 20 },
                  { label: '0.2-0.4', value: 35 },
                  { label: '0.4-0.6', value: 28 },
                  { label: '0.6-0.8', value: 18 },
                  { label: '0.8-1.0', value: kpiData?.alertsEmitted || 7 },
                ]}
              />
            </div>

            <div className="glass-panel p-4 h-full">
              <RegimeContextBadge
                label={kpiData?.regimeDescription || 'Normal Operations'}
                since="00:00 UTC+5:45"
                fpr={`${kpiData?.falsePositiveRate || 0}%`}
              />
            </div>
          </div>
        </div>

        {/* RIGHT: alert feed + system health */}
        <div className="xl:col-span-5 flex flex-col gap-4 self-start">
          <div className="glass-panel p-4 flex flex-col min-h-0">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Live Alert Feed</h2>
              <span className="challenge-badge challenge-badge-c3">C3</span>
            </div>
            <div className="flex-1 overflow-hidden">
              <AlertFeed />
            </div>
          </div>

          <div className="glass-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">System Health</h2>
              <span className={`live-badge ${(kpiData?.intelFeedAgeMin ?? 999) < 60 ? 'live-badge-active' : 'live-badge-inactive'}`}>
                <span className={(kpiData?.intelFeedAgeMin ?? 999) < 60 ? 'status-dot-online' : 'status-dot-offline'} style={{ width: 5, height: 5 }} />
                {(kpiData?.intelFeedAgeMin ?? 999) < 60 ? 'HEALTHY' : 'ATTENTION'}
              </span>
            </div>

            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-background-elevated border border-background-border">
                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Pipeline Mode</div>
                <div className="text-sm font-semibold text-white">{kpiData?.regimeDescription || 'Normal Operations'}</div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-background-elevated border border-background-border">
                  <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Threats Today</div>
                  <div className="text-lg font-bold text-white tabular-nums">{kpiData?.threatsToday ?? 0}</div>
                </div>
                <div className="p-3 rounded-lg bg-background-elevated border border-background-border">
                  <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Alerts Emitted</div>
                  <div className="text-lg font-bold text-white tabular-nums">{kpiData?.alertsEmitted ?? 0}</div>
                </div>
                <div className="p-3 rounded-lg bg-background-elevated border border-background-border">
                  <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">False Positive Rate</div>
                  <div className="text-lg font-bold text-white tabular-nums">{kpiData?.falsePositiveRate ?? 0}%</div>
                </div>
                <div className="p-3 rounded-lg bg-background-elevated border border-background-border">
                  <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Mean Response</div>
                  <div className="text-lg font-bold text-white tabular-nums">{kpiData?.meanResponseTimeMs ?? 0}ms</div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-background-elevated border border-background-border">
                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Intel Feed Freshness</div>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-semibold text-white">{kpiData?.intelFeedAgeMin ?? '—'} min old</div>
                  <div className="text-[10px] text-text-muted text-right max-w-[120px]">
                    {(kpiData?.intelFeedAgeMin ?? 999) < 60 ? 'Live feed is within the active update window.' : 'Threat intel should be checked for staleness.'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Grid: balanced evidence cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-stretch">
        {/* Encrypted Traffic [C4] */}
        <div className="animate-fade-up animate-delay-3 h-full">
          <EncryptedTrafficPanel />
        </div>

        {/* MITRE Navigator */}
        <div className="animate-fade-up animate-delay-4 h-full">
          <div className="glass-panel p-4 h-full flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">MITRE ATT&CK Coverage</span>
              <div className="flex gap-1">
                <span className="challenge-badge challenge-badge-c1">C1</span>
                <span className="challenge-badge challenge-badge-c4">C4</span>
              </div>
            </div>
            <div className="flex-1 flex items-center">
              <MITRENavigator techniques={['T1071.001', 'T1046', 'T1213', 'T1021', 'T1078', 'T1048']} />
            </div>
          </div>
        </div>

        {/* SHAP Explanation */}
        <div className="animate-fade-up animate-delay-5 h-full">
          <div className="glass-panel p-4 h-full flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">SHAP Explanation</span>
              <div className="flex gap-1">
                <span className="challenge-badge challenge-badge-c1">C1</span>
                <span className="challenge-badge challenge-badge-c4">C4</span>
              </div>
            </div>
            <div className="flex-1">
              <SHAPExplanation
                features={[
                  { name: 'JA3 match', value: 0.32 },
                  { name: 'IAT entropy', value: 0.28 },
                  { name: 'Flow duration', value: 0.18 },
                  { name: 'Recon error', value: 0.15 },
                ]}
                summary="Evidence points to beaconing behavior with high TLS fingerprint confidence."
              />
            </div>
          </div>
        </div>

        {/* Audit Chain */}
        <div className="animate-fade-up animate-delay-5 h-full">
          <div className="glass-panel p-4 h-full flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Audit Chain</span>
              <span className="challenge-badge challenge-badge-c3">C3</span>
            </div>
            <div className="flex-1 overflow-hidden">
              <AuditChainViewer entries={auditData?.data || []} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
