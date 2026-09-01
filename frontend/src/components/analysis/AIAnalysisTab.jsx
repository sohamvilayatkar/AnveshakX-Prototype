import React from 'react';
import { Cpu, AlertTriangle, CheckCircle, Activity, Sparkles, Zap, ShieldAlert, BarChart3, HelpCircle } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export const AIAnalysisTab = ({ mlAnalysis, socialEngineering, anomalyDetection }) => {
  if (!mlAnalysis) return null;

  const {
    model_name = 'anveshakx-email-classifier',
    model_version = 'v2.0',
    classification = 'UNCLASSIFIED',
    confidence = 0.50,
    probabilities = {},
    linguistic_signals = []
  } = mlAnalysis;

  const socialDimensions = [
    { key: 'urgency', label: 'Urgency', value: socialEngineering?.urgency || 0.0, desc: 'Artificial deadlines & pressure tactics' },
    { key: 'financial_pressure', label: 'Financial Pressure', value: socialEngineering?.financial_pressure || 0.0, desc: 'Wire transfer, payment, or banking change solicitation' },
    { key: 'authority', label: 'Authority Impersonation', value: socialEngineering?.authority || 0.0, desc: 'Executive, legal, or administrative role pretext' },
    { key: 'fear', label: 'Fear / Coercion', value: socialEngineering?.fear || 0.0, desc: 'Account suspension, penalty, or legal threats' },
    { key: 'secrecy', label: 'Secrecy / Isolation', value: socialEngineering?.secrecy || 0.0, desc: 'Instructions to avoid phone verification or disclosure' },
    { key: 'credential_request', label: 'Credential Request', value: socialEngineering?.credential_request || 0.0, desc: 'Password, MFA token, or login verification solicitation' },
    { key: 'call_to_action', label: 'Call to Action', value: socialEngineering?.call_to_action || 0.0, desc: 'Direct links or urgent action mandates' }
  ];

  const getMeterColor = (val) => {
    if (val >= 0.75) return 'bg-red-500 text-red-400';
    if (val >= 0.50) return 'bg-orange-500 text-orange-400';
    if (val >= 0.25) return 'bg-amber-500 text-amber-400';
    return 'bg-emerald-500 text-emerald-400';
  };

  return (
    <div className="space-y-6 font-mono">
      {/* Top Banner: Model Metadata & Prediction */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Classifier Outcome */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-6 flex flex-col items-center justify-center text-center space-y-3">
          <div className="p-3 rounded-2xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <Cpu className="h-8 w-8 animate-pulse" />
          </div>
          <div>
            <span className="text-[10px] text-soc-muted uppercase tracking-wider block">
              AI Primary Threat Prediction
            </span>
            <h3 className="text-base font-bold text-white mt-1">
              {classification}
            </h3>
            <span className="inline-block mt-2 px-3 py-1 rounded-full bg-purple-500/20 border border-purple-500/40 text-purple-300 font-bold text-xs">
              {Math.round(confidence * 100)}% Model Confidence
            </span>
          </div>
          <div className="text-[10px] text-soc-muted pt-1">
            Engine: {model_name} ({model_version})
          </div>
        </div>

        {/* Card 2: Multi-Class Probability Distribution */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              Multi-Class Model Probability Distribution
            </h3>
            <span className="text-[10px] text-soc-muted">Calibrated Softmax</span>
          </div>

          <div className="space-y-2.5 pt-1 text-xs">
            {Object.entries(probabilities).map(([clsKey, prob]) => {
              const pct = Math.round(prob * 100);
              const isTop = prob === Math.max(...Object.values(probabilities));
              const labelMap = {
                bec: 'Business Email Compromise (BEC)',
                phishing: 'Credential Phishing',
                credential_theft: 'Credential Theft',
                financial_fraud: 'Financial / Wire Fraud',
                legitimate: 'Legitimate Communication'
              };

              return (
                <div key={clsKey} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className={isTop ? 'text-white font-bold' : 'text-soc-muted'}>
                      {labelMap[clsKey] || clsKey}
                    </span>
                    <span className={isTop ? 'text-cyan-400 font-bold' : 'text-soc-muted'}>
                      {pct}%
                    </span>
                  </div>
                  <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${isTop ? 'bg-cyan-400' : 'bg-slate-600'} transition-all duration-500`}
                      style={{ width: `${Math.max(pct, 2)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Social Engineering Profiler */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-soc-border pb-3">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Social Engineering Behavioral Profiler
            </h3>
            <p className="text-xs text-soc-muted">
              Psychological coercion, urgency, authority, and financial manipulation analysis.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {socialDimensions.map((dim) => {
            const pct = Math.round(dim.value * 100);
            const colorClass = getMeterColor(dim.value);

            return (
              <div key={dim.key} className="p-3.5 rounded-lg bg-black/40 border border-soc-border space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">{dim.label}</span>
                  <span className={`font-bold ${colorClass.split(' ')[1]}`}>
                    {pct}%
                  </span>
                </div>
                <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${colorClass.split(' ')[0]} transition-all duration-500`}
                    style={{ width: `${Math.max(pct, 2)}%` }}
                  />
                </div>
                <p className="text-[10px] text-soc-muted truncate" title={dim.desc}>
                  {dim.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* XAI Linguistic Indicators & Anomaly Detector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* XAI Linguistic Feature Importance */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-purple-400" />
              High-Impact Linguistic Features (XAI Attribution)
            </h3>
            <span className="text-[10px] text-soc-muted">TF-IDF Vector Weights</span>
          </div>

          {linguistic_signals.length === 0 ? (
            <p className="text-xs text-soc-muted py-4">No distinctive high-impact threat terms identified.</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              {linguistic_signals.map((sig, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-cyan-300">
                      '{sig.token}'
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      +{sig.weight}
                    </span>
                  </div>
                  <p className="text-[11px] text-soc-muted leading-relaxed">
                    {sig.description}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Unsupervised Anomaly Detection Card */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
          <div className="border-b border-soc-border pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" />
              Structural Anomaly Detector
            </h3>
            <span className="text-[10px] text-soc-muted">Isolation Forest Profile</span>
          </div>

          <div className="p-3.5 rounded-lg bg-black/40 border border-soc-border space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-soc-muted">Status:</span>
              <span className={`font-bold px-2 py-0.5 rounded ${anomalyDetection?.is_anomaly ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'}`}>
                {anomalyDetection?.is_anomaly ? 'ANOMALY DETECTED' : 'NORMAL PROFILE'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-soc-muted">Anomaly Score:</span>
              <span className="font-bold text-white">
                {Math.round((anomalyDetection?.anomaly_score || 0) * 100)}%
              </span>
            </div>

            <p className="text-[11px] text-soc-muted pt-1 leading-relaxed">
              {anomalyDetection?.explanation || 'Statistical pattern comparison against baseline email attributes.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIAnalysisTab;
