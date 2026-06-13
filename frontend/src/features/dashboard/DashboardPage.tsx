import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { AgentHealthPanel } from '@components/feature/AgentHealthPanel';
import { AttackGraph } from '@components/feature/AttackGraph';
import { AlertFeed } from '@components/feature/AlertFeed';
import { EncryptedTrafficPanel } from '@components/feature/EncryptedTrafficPanel';
import { RegimeContextBadge } from '@components/feature/RegimeContextBadge';
import { MITRENavigator } from '@components/feature/MITRENavigator';
import { SHAPExplanation } from '@components/feature/SHAPExplanation';
import { SOCChatWidget } from '@components/feature/SOCChatWidget';
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

      {/* Main Grid: 3 columns */}
      <div className="flex flex-col lg:grid lg:grid-cols-12 gap-4">
        {/* LEFT: Attack Graph [C1] + CRS + Regime Badge */}
        <div className="lg:col-span-5 space-y-4">
          <div className="glass-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Network Threat Topology</h2>
              <span className="challenge-badge challenge-badge-c1">C1</span>
            </div>
            <AttackGraph />
          </div>

          <div className="glass-panel p-4">
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

          <RegimeContextBadge
            label={kpiData?.regimeDescription || 'Normal Operations'}
            since="00:00 UTC+5:45"
            fpr={`${kpiData?.falsePositiveRate || 0}%`}
          />
        </div>

        {/* CENTER: Alert Feed [C3] */}
        <div className="lg:col-span-4 space-y-4">
          <div className="glass-panel p-4 h-[600px] lg:h-full flex flex-col min-h-0">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Live Alert Feed</h2>
              <span className="challenge-badge challenge-badge-c3">C3</span>
            </div>
            <div className="flex-1 overflow-hidden">
              <AlertFeed />
            </div>
          </div>
        </div>

        {/* RIGHT: SOC Assistant [C3] */}
        <div className="lg:col-span-3 space-y-4">
          <div className="h-[500px] lg:h-full">
             <SOCChatWidget />
          </div>
        </div>
      </div>

      {/* Bottom Grid: 3 equal columns */}
      <div className="flex flex-col lg:grid lg:grid-cols-3 gap-4">
        {/* Encrypted Traffic [C4] */}
        <div className="animate-fade-up animate-delay-3">
          <EncryptedTrafficPanel />
        </div>

        {/* MITRE Navigator */}
        <div className="animate-fade-up animate-delay-4">
          <div className="glass-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">MITRE ATT&CK Coverage</span>
              <div className="flex gap-1">
                <span className="challenge-badge challenge-badge-c1">C1</span>
                <span className="challenge-badge challenge-badge-c4">C4</span>
              </div>
            </div>
            <MITRENavigator techniques={['T1071.001', 'T1046', 'T1213', 'T1021', 'T1078', 'T1048']} />
          </div>
        </div>

        {/* SHAP + Audit */}
        <div className="space-y-4 animate-fade-up animate-delay-5">
          <div className="glass-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">SHAP Explanation</span>
              <div className="flex gap-1">
                <span className="challenge-badge challenge-badge-c1">C1</span>
                <span className="challenge-badge challenge-badge-c4">C4</span>
              </div>
            </div>
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

          <div className="glass-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Audit Chain</span>
              <span className="challenge-badge challenge-badge-c3">C3</span>
            </div>
            <AuditChainViewer entries={auditData?.data || []} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
