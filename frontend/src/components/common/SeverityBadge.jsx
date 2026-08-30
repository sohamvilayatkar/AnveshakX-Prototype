import React from 'react';
import { AlertOctagon, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';

export const SeverityBadge = ({ severity, size = 'md' }) => {
  const sev = (severity || 'LOW').toUpperCase();

  const configs = {
    CRITICAL: {
      bg: 'bg-red-500/10 text-red-400 border-red-500/30',
      dot: 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]',
      icon: AlertOctagon
    },
    HIGH: {
      bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
      dot: 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]',
      icon: AlertTriangle
    },
    MEDIUM: {
      bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      dot: 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]',
      icon: Info
    },
    LOW: {
      bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      dot: 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]',
      icon: CheckCircle2
    },
    INFO: {
      bg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      dot: 'bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.8)]',
      icon: Info
    }
  };

  const current = configs[sev] || configs.LOW;
  const Icon = current.icon;
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-mono font-semibold uppercase tracking-wide ${current.bg} ${sizeClasses}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${current.dot}`} />
      <Icon className="h-3.5 w-3.5" />
      {sev}
    </span>
  );
};

export default SeverityBadge;
