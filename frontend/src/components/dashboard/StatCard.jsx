import React from 'react';

export const StatCard = ({ title, value, subtitle, icon: Icon, color = 'cyan', badge }) => {
  const colorMap = {
    cyan: 'from-cyan-500/10 to-transparent border-cyan-500/20 text-cyan-400',
    red: 'from-red-500/10 to-transparent border-red-500/20 text-red-400',
    orange: 'from-orange-500/10 to-transparent border-orange-500/20 text-orange-400',
    amber: 'from-amber-500/10 to-transparent border-amber-500/20 text-amber-400',
    emerald: 'from-emerald-500/10 to-transparent border-emerald-500/20 text-emerald-400'
  };

  const current = colorMap[color] || colorMap.cyan;

  return (
    <div className={`relative overflow-hidden rounded-xl border bg-gradient-to-b ${current} bg-soc-card p-5 transition-all hover:border-opacity-50 hover:shadow-lg`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono uppercase tracking-wider text-soc-muted">{title}</span>
        {Icon && (
          <div className="p-2 rounded-lg bg-black/30 border border-soc-border text-current">
            <Icon className="h-5 w-5" />
          </div>
        )}
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-3xl font-bold font-mono tracking-tight text-white">{value}</span>
        {badge && (
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-black/40 border border-soc-border text-soc-muted">
            {badge}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="mt-2 text-xs text-soc-muted flex items-center gap-1 truncate">
          {subtitle}
        </p>
      )}
    </div>
  );
};

export default StatCard;
