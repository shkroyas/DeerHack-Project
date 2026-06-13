import React, { useState } from 'react';
import { Swords, Play, CheckCircle, Clock, AlertTriangle, TrendingDown, Zap } from 'lucide-react';

interface ScenarioInfo {
  id: string;
  challenge: string;
  name: string;
  description: string;
  expected_time: string;
  stages: string[];
}

interface StageEvent {
  stage_index: number;
  timestamp_offset_sec: number;
  challenge: string;
  agent: string;
  event: string;
  detection: string | null;
  confidence: number;
  latency_ms: number;
}

interface ScenarioResult {
  scenario_id: string;
  scenario_name: string;
  challenge: string;
  description: string;
  stages: StageEvent[];
  total_detection_time_sec: number;
  alerts_generated: number;
  alerts_after_suppression: number;
  campaign_ticket_id: string | null;
  success: boolean;
}

const CHALLENGE_ICONS: Record<string, React.ReactNode> = {
  C1: <AlertTriangle size={16} />,
  C2: <TrendingDown size={16} />,
  C3: <Zap size={16} />,
  C4: <Swords size={16} />,
};

const CHALLENGE_COLORS: Record<string, { bg: string; border: string; text: string; badge: string; glow: string }> = {
  C1: { bg: 'rgba(20,184,166,0.05)', border: 'rgba(20,184,166,0.2)', text: 'text-challenge-c1', badge: 'challenge-badge-c1', glow: 'glow-c1' },
  C2: { bg: 'rgba(245,158,11,0.05)', border: 'rgba(245,158,11,0.2)', text: 'text-challenge-c2', badge: 'challenge-badge-c2', glow: 'glow-c2' },
  C3: { bg: 'rgba(139,92,246,0.05)', border: 'rgba(139,92,246,0.2)', text: 'text-challenge-c3', badge: 'challenge-badge-c3', glow: 'glow-c3' },
  C4: { bg: 'rgba(59,130,246,0.05)', border: 'rgba(59,130,246,0.2)', text: 'text-challenge-c4', badge: 'challenge-badge-c4', glow: 'glow-c4' },
};

const RedTeamPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [activeResult, setActiveResult] = useState<ScenarioResult | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [loadedScenarios, setLoadedScenarios] = useState(false);

  const loadScenarios = async () => {
    try {
      const res = await fetch(`${(`http://${window.location.hostname}:8000`)}/redteam/scenarios`);
      if (res.ok) {
        setScenarios(await res.json());
        setLoadedScenarios(true);
      }
    } catch {
      // Use defaults
      setScenarios([
        { id: 'swift_c2', challenge: 'C4', name: 'SWIFT C2 Beaconing', description: 'Cobalt Strike C2 from SWIFT subnet — 3-layer TLS detection', expected_time: '38s', stages: ['TLS C2 Channel', 'Lateral Movement', 'DB Collection'] },
        { id: 'atm_harvest', challenge: 'C2', name: 'ATM PIN Harvesting', description: 'Attack during ATM reconciliation — context-aware detection', expected_time: '52s', stages: ['ATM Recon', 'MitM Injection', 'Exfiltration'] },
        { id: 'insider_exfil', challenge: 'C1', name: 'Insider Zero-Day Exfil', description: 'Novel exfiltration with no known signature — BiLSTM fires', expected_time: '71s', stages: ['Off-hours Access', 'Novel Queries', 'Encrypted Exfil'] },
        { id: 'ransomware_spread', challenge: 'C3', name: 'Ransomware Spread', description: '412 alerts collapsed to 1 campaign ticket', expected_time: '44s', stages: ['Initial Compromise', 'RDP Spread', 'Encryption'] },
      ]);
      setLoadedScenarios(true);
    }
  };

  if (!loadedScenarios) loadScenarios();

  const runScenario = async (scenarioId: string) => {
    setLoading(scenarioId);
    setActiveResult(null);
    try {
      const res = await fetch(`${(`http://${window.location.hostname}:8000`)}/redteam/${scenarioId}`, {
        method: 'POST',
      });
      if (res.ok) {
        setActiveResult(await res.json());
      }
    } catch {
      // Connection error
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="p-4 space-y-6 animate-fade-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
              <Swords size={16} className="text-white" />
            </div>
            Red Team Mode
          </h1>
          <p className="text-xs text-text-muted mt-1">Challenge-mapped attack scenarios with real model inference</p>
        </div>
      </div>

      {/* Scenario Cards */}
      <div className="grid grid-cols-2 gap-4">
        {scenarios.map((s, i) => {
          const c = CHALLENGE_COLORS[s.challenge] || CHALLENGE_COLORS.C1;
          const isRunning = loading === s.id;
          return (
            <div
              key={s.id}
              className={`glass-panel p-5 ${c.glow} animate-fade-up transition-all hover:scale-[1.01]`}
              style={{ animationDelay: `${i * 80}ms`, borderColor: c.border }}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className={c.text}>{CHALLENGE_ICONS[s.challenge]}</span>
                  <h3 className="text-sm font-semibold text-white">{s.name}</h3>
                </div>
                <span className={`challenge-badge ${c.badge}`}>{s.challenge}</span>
              </div>

              <p className="text-xs text-text-secondary mb-4 leading-relaxed">{s.description}</p>

              <div className="flex items-center gap-4 mb-4">
                <div className="flex items-center gap-1.5 text-[10px] text-text-muted">
                  <Clock size={10} />
                  Expected: {s.expected_time}
                </div>
                <div className="text-[10px] text-text-muted">
                  {s.stages.length} stages
                </div>
              </div>

              {/* Stages preview */}
              <div className="space-y-1.5 mb-4">
                {s.stages.map((stage, si) => (
                  <div key={si} className="flex items-center gap-2 text-[10px] text-text-muted">
                    <span className="font-mono text-text-muted opacity-50">0{si + 1}</span>
                    <span>{stage}</span>
                  </div>
                ))}
              </div>

              <button
                onClick={() => runScenario(s.id)}
                disabled={loading !== null}
                className={`w-full py-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
                  isRunning
                    ? 'bg-background-elevated text-text-muted cursor-wait'
                    : 'btn-danger hover:shadow-glow-red'
                } disabled:opacity-40`}
              >
                {isRunning ? (
                  <>
                    <div className="w-3 h-3 border-2 border-text-muted border-t-transparent rounded-full animate-spin" />
                    Running Pipeline...
                  </>
                ) : (
                  <>
                    <Play size={12} />
                    Launch Scenario
                  </>
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* Results */}
      {activeResult && (
        <div className="glass-panel-elevated p-6 animate-fade-up glow-critical">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <CheckCircle size={16} className="text-green-400" />
              <h3 className="text-sm font-bold text-white">{activeResult.scenario_name} — Complete</h3>
              <span className={`challenge-badge challenge-badge-${activeResult.challenge.toLowerCase()}`}>
                {activeResult.challenge}
              </span>
            </div>
            <div className="text-xs text-text-secondary font-mono">
              {activeResult.total_detection_time_sec.toFixed(2)}s total
            </div>
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="stat-card">
              <div className="text-[10px] text-text-muted uppercase">Alerts Generated</div>
              <div className="text-lg font-bold text-white">{activeResult.alerts_generated}</div>
            </div>
            <div className="stat-card">
              <div className="text-[10px] text-text-muted uppercase">After Suppression</div>
              <div className="text-lg font-bold text-challenge-c3">{activeResult.alerts_after_suppression}</div>
            </div>
            <div className="stat-card">
              <div className="text-[10px] text-text-muted uppercase">Detection Time</div>
              <div className="text-lg font-bold text-challenge-c4">{activeResult.total_detection_time_sec.toFixed(2)}s</div>
            </div>
            <div className="stat-card">
              <div className="text-[10px] text-text-muted uppercase">Campaign ID</div>
              <div className="text-xs font-mono text-text-secondary truncate">{activeResult.campaign_ticket_id || '—'}</div>
            </div>
          </div>

          {/* Stage Events */}
          <div className="space-y-2">
            {activeResult.stages.map((stage, i) => (
              <div
                key={i}
                className={`redteam-event redteam-event-${stage.challenge.toLowerCase()}`}
                style={{ animationDelay: `${i * 150}ms` }}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-text-muted">T+{stage.timestamp_offset_sec}s</span>
                    <span className={`challenge-badge challenge-badge-${stage.challenge.toLowerCase()}`}>{stage.challenge}</span>
                    <span className="text-[10px] text-text-muted uppercase">{stage.agent}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-text-muted">CRS: {stage.confidence.toFixed(3)}</span>
                    <span className="text-[10px] text-text-muted">{stage.latency_ms.toFixed(0)}ms</span>
                  </div>
                </div>
                <div className="text-xs text-white font-medium">{stage.event}</div>
                {stage.detection && (
                  <div className="text-[10px] text-text-secondary mt-1">↳ {stage.detection}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default RedTeamPage;
