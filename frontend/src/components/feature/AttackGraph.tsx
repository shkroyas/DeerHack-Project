import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '@services/dashboard.service';

const NODE_COLORS: Record<string, string> = {
  safe: '#14b8a6', // c1
  suspicious: '#f59e0b', // c2
  compromised: '#ef4444', // red
  isolated: '#6b7280',
};

const EDGE_COLORS = {
  normal: 'rgba(255,255,255,0.1)',
  attack: 'rgba(245,158,11,0.5)',
  c2: 'rgba(239,68,68,0.5)',
};

export const AttackGraph: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  
  const { data } = useQuery({
    queryKey: ['dashboard', 'graph'],
    queryFn: dashboardService.getGraph,
    refetchInterval: 5000,
  });

  useEffect(() => {
    if (!containerRef.current || !data) return;

    if (!cyRef.current) {
      cyRef.current = cytoscape({
        container: containerRef.current,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': (ele) => NODE_COLORS[ele.data('state') as string] || NODE_COLORS.safe,
              'label': 'data(label)',
              'color': '#fff',
              'font-size': '10px',
              'font-family': 'Inter',
              'text-valign': 'bottom',
              'text-margin-y': 6,
              'width': 24,
              'height': 24,
              'border-width': 2,
              'border-color': 'rgba(255,255,255,0.1)',
            }
          },
          {
            selector: 'edge',
            style: {
              'width': 2,
              'line-color': (ele) => {
                const type = ele.data('type');
                if (type === 'c2-channel') return EDGE_COLORS.c2;
                if (type === 'attack') return EDGE_COLORS.attack;
                return EDGE_COLORS.normal;
              },
              'target-arrow-shape': 'triangle',
              'target-arrow-color': (ele) => {
                const type = ele.data('type');
                if (type === 'c2-channel') return EDGE_COLORS.c2;
                if (type === 'attack') return EDGE_COLORS.attack;
                return EDGE_COLORS.normal;
              },
              'curve-style': 'bezier',
              'label': 'data(label)',
              'font-size': '8px',
              'color': 'rgba(255,255,255,0.5)',
              'text-rotation': 'autorotate',
              'text-margin-y': -8
            }
          }
        ],
        layout: {
          name: 'cose',
          animate: false,
          nodeDimensionsIncludeLabels: true,
          padding: 30
        }
      });
    }

    const cy = cyRef.current;
    cy.elements().remove();
    cy.add(
      data.nodes.map(n => ({ data: { id: n.id, label: n.label, state: n.state, type: n.type } }))
    );
    cy.add(
      data.edges.map(e => ({ data: { id: e.id, source: e.source, target: e.target, label: e.label, type: e.type } }))
    );

    cy.layout({ name: 'cose', animate: false }).run();

    return () => {
      // Don't destroy on unmount to keep cache if possible, but actually we do to prevent memory leaks
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [data]);

  return (
    <div className="relative w-full h-[300px] rounded-lg overflow-hidden cy-container border border-background-border group">
      <div ref={containerRef} className="absolute inset-0" />
      {/* Legend */}
      <div className="absolute top-3 left-3 bg-background-elevated/80 backdrop-blur-sm border border-background-border rounded p-2 flex flex-col gap-1.5 opacity-50 group-hover:opacity-100 transition-opacity">
        <div className="flex items-center gap-1.5 text-[9px] text-white font-medium">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.safe }} /> Normal Node
        </div>
        <div className="flex items-center gap-1.5 text-[9px] text-white font-medium">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.suspicious }} /> Suspicious / Alert
        </div>
        <div className="flex items-center gap-1.5 text-[9px] text-white font-medium">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.compromised }} /> Compromised
        </div>
      </div>
    </div>
  );
};
