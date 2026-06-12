import React from 'react';

interface Props {
  /** MITRE technique id (e.g., T1071.001). */
  technique: string;
}

export const MITRETag: React.FC<Props> = ({ technique }) => {
  return (
    <span className="px-2 py-0.5 rounded border border-background-border text-xs text-text.secondary font-mono">
      {technique}
    </span>
  );
};
