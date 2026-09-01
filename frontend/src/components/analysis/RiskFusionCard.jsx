import React from 'react';
import { Layers, ShieldCheck, Cpu, Globe, ArrowRight } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export const RiskFusionCard = ({ riskFusion, threat }) => {
  if (!riskFusion) return null;

  const {
    forensic_score = 0,
    forensic_weight = 0.50,
    ml_score = 0,
    ml_weight = 0.30,
    intel_score = 0,
    intel_weight = 0.20,
    final_score = threat?.score || 0,
    formula = ""
  } = riskFusion;

  const getBarColor = (score) => {
    if (score >= 80) return 'bg-red-500 text-red-400';
    if (score >= 60) return 'bg-orange-500 text-orange-400';
    if (score >= 30) return 'bg-amber-500 text-amber-400';
    return 'bg-emerald-500 text-emerald-400';
  };

  return (
    <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4 font-mono">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-soc-border pb-3">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            Multi-Layer Risk Fusion Engine
          </h3>
          <p className="text-xs text-soc-muted">
            Weighted synthesis combining Forensic Evidence, AI Language Models, and Threat Intel.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={threat?.severity || 'LOW'} />
          <span className="text-xs px-2 py-0.5 rounded bg-black/50 border border-soc-border text-white font-bold">
            Final: {final_score} / 100
          </span>
        </div>
      </div>

      {/* Tri-Layer Bar Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        {/* Layer 1: Forensic Score */}
        <div className="p-3.5 rounded-lg bg-black/40 border border-soc-border space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-soc-muted flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
              Forensic Evidence
            </span>
            <span className="font-bold text-white">{forensic_score} pts</span>
          </div>
          <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${getBarColor(forensic_score).split(' ')[0]} transition-all duration-500`}
              style={{ width: `${Math.min(forensic_score, 100)}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-soc-muted">
            <span>Weight: {Math.round(forensic_weight * 100)}%</span>
            <span>Contributed: {Math.round(forensic_score * forensic_weight)} pts</span>
          </div>
        </div>

        {/* Layer 2: Machine Learning Score */}
        <div className="p-3.5 rounded-lg bg-black/40 border border-soc-border space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-soc-muted flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5 text-purple-400" />
              AI / ML Linguistic
            </span>
            <span className="font-bold text-white">{ml_score} pts</span>
          </div>
          <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${getBarColor(ml_score).split(' ')[0]} transition-all duration-500`}
              style={{ width: `${Math.min(ml_score, 100)}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-soc-muted">
            <span>Weight: {Math.round(ml_weight * 100)}%</span>
            <span>Contributed: {Math.round(ml_score * ml_weight)} pts</span>
          </div>
        </div>

        {/* Layer 3: Threat Intelligence */}
        <div className="p-3.5 rounded-lg bg-black/40 border border-soc-border space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-soc-muted flex items-center gap-1.5">
              <Globe className="h-3.5 w-3.5 text-amber-400" />
              Threat Intelligence
            </span>
            <span className="font-bold text-white">{intel_score} pts</span>
          </div>
          <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${getBarColor(intel_score).split(' ')[0]} transition-all duration-500`}
              style={{ width: `${Math.min(intel_score, 100)}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-soc-muted">
            <span>Weight: {Math.round(intel_weight * 100)}%</span>
            <span>Contributed: {Math.round(intel_score * intel_weight)} pts</span>
          </div>
        </div>
      </div>

      {/* Formula & Explainability Footer */}
      <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
        <div className="text-soc-muted">
          <span className="text-cyan-400 font-bold">Fusion Formula:</span> {formula}
        </div>
        <span className="text-[11px] text-soc-muted shrink-0">
          Deterministic & Calibrated
        </span>
      </div>
    </div>
  );
};

export default RiskFusionCard;
