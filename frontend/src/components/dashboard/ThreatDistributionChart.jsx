import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

export const ThreatDistributionChart = ({ cases = [] }) => {
  // Compute distribution from cases
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  cases.forEach(c => {
    const sev = (c.severity || 'LOW').toUpperCase();
    if (counts[sev] !== undefined) counts[sev]++;
    else counts.LOW++;
  });

  const data = [
    { name: 'Critical Risk', value: counts.CRITICAL || 0, color: '#ef4444' },
    { name: 'High Risk', value: counts.HIGH || 0, color: '#f97316' },
    { name: 'Medium Risk', value: counts.MEDIUM || 0, color: '#f59e0b' },
    { name: 'Low Risk / Benign', value: counts.LOW || 0, color: '#10b981' }
  ].filter(d => d.value > 0);

  // Default placeholder if empty
  const displayData = data.length > 0 ? data : [
    { name: 'Critical Risk', value: 3, color: '#ef4444' },
    { name: 'High Risk', value: 2, color: '#f97316' },
    { name: 'Medium Risk', value: 1, color: '#f59e0b' },
    { name: 'Low Risk', value: 4, color: '#10b981' }
  ];

  return (
    <div className="rounded-xl border border-soc-border bg-soc-card p-5 h-full flex flex-col justify-between">
      <div>
        <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">Threat Severity Distribution</h3>
        <p className="text-xs text-soc-muted">Breakdown across recorded email forensic cases</p>
      </div>

      <div className="h-56 w-full my-2">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={displayData}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={80}
              paddingAngle={4}
              dataKey="value"
            >
              {displayData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} stroke="#090d16" strokeWidth={2} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#0f172a',
                borderColor: '#1e293b',
                borderRadius: '8px',
                color: '#f8fafc',
                fontFamily: 'monospace'
              }}
            />
            <Legend
              verticalAlign="bottom"
              height={36}
              formatter={(value) => <span className="text-xs font-mono text-soc-muted">{value}</span>}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default ThreatDistributionChart;
