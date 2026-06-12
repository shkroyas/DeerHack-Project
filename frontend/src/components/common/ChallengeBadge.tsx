import React from 'react';

interface Props {
  challenge: 'C1' | 'C2' | 'C3' | 'C4';
}

export const ChallengeBadge: React.FC<Props> = ({ challenge }) => {
  const cls = {
    C1: 'bg-teal-500/20 text-teal-400 border border-teal-500/30',
    C2: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
    C3: 'bg-purple-500/20 text-purple-400 border border-purple-500/30',
    C4: 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
  }[challenge];

  return <span className={`px-2 py-1 text-xs rounded ${cls} font-mono`}>{challenge}</span>;
};
