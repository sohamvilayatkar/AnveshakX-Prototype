import React from 'react';
import { Target, GitMerge, CheckCircle, ShieldAlert, Tag, ExternalLink } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export const CampaignSimilarityTab = ({ campaignMatches = [] }) => {
  return (
    <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4 font-mono">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-soc-border pb-3">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
            <Target className="h-4 w-4 text-cyan-400" />
            Threat Campaign & Historical Case Correlation
          </h3>
          <p className="text-xs text-soc-muted">
            Semantic similarity matching across known cyber threat campaign signatures and stored case records.
          </p>
        </div>
        <span className="text-xs px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
          {campaignMatches.length} Matches Found
        </span>
      </div>

      {campaignMatches.length === 0 ? (
        <div className="p-8 rounded-lg bg-black/30 border border-soc-border text-center space-y-2">
          <CheckCircle className="h-8 w-8 text-emerald-400 mx-auto" />
          <p className="text-xs text-white font-bold">No Related Threat Campaign Signatures Found</p>
          <p className="text-[11px] text-soc-muted max-w-md mx-auto">
            This email does not correlate with known threat cluster signatures or previous case investigations.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {campaignMatches.map((match, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-black/40 border border-soc-border space-y-3 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    {match.campaign_id}
                  </span>
                  <span className="text-xs font-bold text-cyan-400 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                    {match.similarity_percent}% Similarity
                  </span>
                </div>

                <h4 className="text-sm font-bold text-white leading-snug">
                  {match.campaign_name}
                </h4>

                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-400 to-purple-500 transition-all duration-500"
                    style={{ width: `${match.similarity_percent}%` }}
                  />
                </div>
              </div>

              <div className="space-y-1.5 pt-2 border-t border-soc-border">
                <span className="text-[10px] text-soc-muted uppercase tracking-wider block">
                  Shared Forensic Characteristics:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {match.shared_traits.map((trait, tIdx) => (
                    <span
                      key={tIdx}
                      className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-soc-muted"
                    >
                      &bull; {trait}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default CampaignSimilarityTab;
