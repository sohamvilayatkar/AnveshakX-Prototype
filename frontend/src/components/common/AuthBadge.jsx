import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldMinus, HelpCircle } from 'lucide-react';

export const AuthBadge = ({ protocol, result }) => {
  const res = (result || 'NONE').toUpperCase();

  const configs = {
    PASS: {
      bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      icon: ShieldCheck,
      text: 'PASS'
    },
    FAIL: {
      bg: 'bg-red-500/10 text-red-400 border-red-500/30',
      icon: ShieldAlert,
      text: 'FAIL'
    },
    SOFTFAIL: {
      bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      icon: ShieldMinus,
      text: 'SOFTFAIL'
    },
    NEUTRAL: {
      bg: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      icon: HelpCircle,
      text: 'NEUTRAL'
    },
    NONE: {
      bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
      icon: ShieldMinus,
      text: 'NONE'
    }
  };

  const current = configs[res] || configs.NONE;
  const Icon = current.icon;

  return (
    <div className={`flex items-center justify-between p-3 rounded-lg border bg-soc-card ${current.bg}`}>
      <div className="flex items-center gap-2">
        <Icon className="h-5 w-5" />
        <span className="font-bold text-sm tracking-wider font-mono">{protocol}</span>
      </div>
      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-black/40 border border-current">
        {current.text}
      </span>
    </div>
  );
};

export default AuthBadge;
