import React from 'react';
import { ShieldAlert, Cpu, Globe, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export const WhyFlaggedCard = ({ riskFusion }) => {
  if (!riskFusion) return null;

  const { technical_evidence = [], ai_evidence = [], intel_evidence = [] } = riskFusion;

  return (
    <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
      <div className="border-b border-soc-border pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-cyan-400" />
            Why Was This Email Flagged? (Explainable XAI Triage)
          </h3>
          <p className="text-xs text-soc-muted">
            Multi-layer attribution correlating Technical Inconsistencies, AI Linguistic Signals, and Threat Intelligence.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Pane 1: Technical Forensic Evidence */}
        <div className="p-4 rounded-lg bg-black/40 border border-soc-border space-y-3">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <span className="font-mono font-bold text-xs text-cyan-300 flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5" />
              1. Technical Evidence
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {technical_evidence.length} Signals
            </span>
          </div>

          <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
            {technical_evidence.length === 0 ? (
              <p className="text-xs font-mono text-soc-muted py-2 flex items-center gap-1.5">
                <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                No technical header anomalies.
              </p>
            ) : (
              technical_evidence.map((item, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-[11px] truncate" title={item.title}>
                      {item.title}
                    </span>
                    <SeverityBadge severity={item.severity} size="sm" />
                  </div>
                  <p className="text-[11px] text-soc-muted leading-relaxed">
                    {item.explanation}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Pane 2: AI & Linguistic Signals */}
        <div className="p-4 rounded-lg bg-black/40 border border-soc-border space-y-3">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <span className="font-mono font-bold text-xs text-purple-300 flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5" />
              2. AI & Behavioral Evidence
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
              {ai_evidence.length} Signals
            </span>
          </div>

          <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
            {ai_evidence.length === 0 ? (
              <p className="text-xs font-mono text-soc-muted py-2 flex items-center gap-1.5">
                <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                No malicious linguistic signals.
              </p>
            ) : (
              ai_evidence.map((item, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-[11px] truncate" title={item.title}>
                      {item.title}
                    </span>
                    <SeverityBadge severity={item.severity} size="sm" />
                  </div>
                  <p className="text-[11px] text-soc-muted leading-relaxed">
                    {item.explanation}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Pane 3: Threat Intelligence */}
        <div className="p-4 rounded-lg bg-black/40 border border-soc-border space-y-3">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <span className="font-mono font-bold text-xs text-amber-300 flex items-center gap-1.5">
              <Globe className="h-3.5 w-3.5" />
              3. Threat Intelligence
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
              {intel_evidence.length} Signals
            </span>
          </div>

          <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
            {intel_evidence.length === 0 ? (
              <p className="text-xs font-mono text-soc-muted py-2 flex items-center gap-1.5">
                <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                Infrastructure reputation is clear.
              </p>
            ) : (
              intel_evidence.map((item, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-[11px] truncate" title={item.title}>
                      {item.title}
                    </span>
                    <SeverityBadge severity={item.severity} size="sm" />
                  </div>
                  <p className="text-[11px] text-soc-muted leading-relaxed">
                    {item.explanation}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default WhyFlaggedCard;
