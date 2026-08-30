import React from 'react';
import { Link } from 'react-router-dom';
import { FileText, ExternalLink, Hash, Clock } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export const RecentCasesTable = ({ cases = [], loading = false }) => {
  return (
    <div className="rounded-xl border border-soc-border bg-soc-card p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">Recent Investigations</h3>
          <p className="text-xs text-soc-muted">Latest forensic cases analyzed</p>
        </div>
        <Link
          to="/cases"
          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
        >
          View All <ExternalLink className="h-3 w-3" />
        </Link>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-black/30 text-soc-muted uppercase border-b border-soc-border">
            <tr>
              <th className="px-3 py-2.5">Case ID</th>
              <th className="px-3 py-2.5">Filename</th>
              <th className="px-3 py-2.5">Threat Score</th>
              <th className="px-3 py-2.5">Severity</th>
              <th className="px-3 py-2.5">Classification</th>
              <th className="px-3 py-2.5 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border">
            {loading ? (
              <tr>
                <td colSpan="6" className="text-center py-8 text-soc-muted">
                  Loading investigation registry...
                </td>
              </tr>
            ) : cases.length === 0 ? (
              <tr>
                <td colSpan="6" className="text-center py-8 text-soc-muted">
                  No cases recorded yet. Upload an .eml email or load a demo sample to begin analysis.
                </td>
              </tr>
            ) : (
              cases.slice(0, 6).map((c) => (
                <tr key={c.id} className="hover:bg-soc-cardHover/50 transition-colors">
                  <td className="px-3 py-3 font-bold text-cyan-400">
                    <Link to={`/analysis?case_id=${c.id}`} className="hover:underline flex items-center gap-1.5">
                      <Hash className="h-3.5 w-3.5 text-cyan-500" />
                      {c.id}
                    </Link>
                  </td>
                  <td className="px-3 py-3 text-white max-w-[180px] truncate">
                    {c.filename}
                  </td>
                  <td className="px-3 py-3 font-bold">
                    <span className={c.threat_score >= 80 ? 'text-red-400' : c.threat_score >= 60 ? 'text-orange-400' : c.threat_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                      {c.threat_score} / 100
                    </span>
                  </td>
                  <td className="px-3 py-3">
                    <SeverityBadge severity={c.severity} size="sm" />
                  </td>
                  <td className="px-3 py-3 text-soc-muted max-w-[150px] truncate">
                    {c.classification}
                  </td>
                  <td className="px-3 py-3 text-right">
                    <Link
                      to={`/analysis?case_id=${c.id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-[11px] transition-colors"
                    >
                      <FileText className="h-3 w-3" />
                      Inspect
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default RecentCasesTable;
