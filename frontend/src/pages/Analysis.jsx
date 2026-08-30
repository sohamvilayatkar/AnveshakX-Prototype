import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, Globe, Server, Link2, Paperclip,
  Activity, Clock, GitFork, KeyRound, Download, Copy, Check, FileText,
  HelpCircle, Eye, ArrowRight, ArrowDown, ChevronRight, Hash, Terminal
} from 'lucide-react';
import api from '../services/api';
import SeverityBadge from '../components/common/SeverityBadge';
import AuthBadge from '../components/common/AuthBadge';
import AttackGraph from '../components/graph/AttackGraph';
import GeoMap from '../components/map/GeoMap';

export const Analysis = () => {
  const [searchParams] = useSearchParams();
  const caseIdParam = searchParams.get('case_id');
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [copiedHash, setCopiedHash] = useState(false);

  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        setLoading(true);
        // Check session storage first
        const cached = sessionStorage.getItem('current_analysis');
        if (cached) {
          const parsed = JSON.parse(cached);
          if (!caseIdParam || parsed.case?.id === caseIdParam) {
            setAnalysis(parsed);
            setLoading(false);
            return;
          }
        }

        // Fetch from API
        if (caseIdParam) {
          const data = await api.getCaseAnalysis(caseIdParam);
          setAnalysis(data);
          sessionStorage.setItem('current_analysis', JSON.stringify(data));
        } else {
          // Default load bec demo if no case specified
          const data = await api.loadSampleEmail('bec');
          setAnalysis(data);
          sessionStorage.setItem('current_analysis', JSON.stringify(data));
        }
      } catch (err) {
        console.error(err);
        setError(err.response?.data?.detail || 'Failed to load forensic analysis.');
      } finally {
        setLoading(false);
      }
    };

    fetchAnalysis();
  }, [caseIdParam]);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  if (loading) {
    return (
      <div className="h-[70vh] flex flex-col items-center justify-center space-y-4">
        <div className="h-10 w-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="font-mono text-xs text-soc-muted animate-pulse">
          Correlating headers, relay path, IOCs, and explainable threat scoring...
        </p>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="p-8 rounded-xl border border-red-500/30 bg-red-500/10 text-center space-y-4 max-w-xl mx-auto my-12">
        <AlertTriangle className="h-10 w-10 text-red-400 mx-auto" />
        <h2 className="text-lg font-mono font-bold text-white">Investigation Data Unavailable</h2>
        <p className="text-xs text-soc-muted">{error || 'Case could not be found or loaded.'}</p>
        <Link
          to="/upload"
          className="inline-block px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-mono font-bold text-xs"
        >
          Analyze An Email
        </Link>
      </div>
    );
  }

  const { case: caseData, email, threat, authentication, header_findings, relay_path, ips, domains, urls, attachments, iocs, risk_factors, timeline, graph, evidence } = analysis;

  const tabs = [
    { id: 'overview', label: 'Threat Overview', icon: Activity },
    { id: 'headers', label: 'Header Forensics', icon: FileText, count: header_findings.length },
    { id: 'auth', label: 'Authentication', icon: ShieldCheck },
    { id: 'relay', label: 'Relay Path', icon: GitFork, count: relay_path.length },
    { id: 'urls', label: 'URLs & Domains', icon: Link2, count: urls.length },
    { id: 'attachments', label: 'Attachments', icon: Paperclip, count: attachments.length },
    { id: 'geo', label: 'Geo & ASN Map', icon: Globe, count: ips.length },
    { id: 'iocs', label: 'IOC Registry', icon: Hash, count: iocs.length },
    { id: 'graph', label: 'Attack Graph', icon: GitFork },
    { id: 'timeline', label: 'Timeline', icon: Clock, count: timeline.length },
    { id: 'evidence', label: 'Evidence Integrity', icon: KeyRound }
  ];

  const scoreColor = threat.score >= 80 ? 'text-red-400 border-red-500' : threat.score >= 60 ? 'text-orange-400 border-orange-500' : threat.score >= 30 ? 'text-amber-400 border-amber-500' : 'text-emerald-400 border-emerald-500';

  return (
    <div className="space-y-6">
      {/* Master Case Header */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-soc-border pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-lg text-white">{caseData.id}</span>
              <SeverityBadge severity={threat.severity} />
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-black/40 border border-soc-border text-cyan-400">
                {threat.classification}
              </span>
            </div>
            <p className="text-xs font-mono text-soc-muted truncate max-w-xl">
              Subject: <span className="text-white font-medium">{email.subject || '(No Subject)'}</span>
            </p>
          </div>

          <div className="flex items-center gap-3">
            <a
              href={api.getReportPdfUrl(caseData.id)}
              download={`AnveshakX_${caseData.id}.pdf`}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)]"
            >
              <Download className="h-4 w-4" />
              Forensic PDF Report
            </a>
          </div>
        </div>

        {/* Identity & Evidence Quick Strip */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 rounded-lg bg-black/30 border border-soc-border">
            <span className="text-soc-muted block text-[10px] uppercase">Claimed From</span>
            <span className="text-white font-semibold truncate block" title={email.sender.email}>
              {email.sender.display_name ? `${email.sender.display_name} <${email.sender.email}>` : email.sender.email}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-black/30 border border-soc-border">
            <span className="text-soc-muted block text-[10px] uppercase">Reply-To Routing</span>
            <span className={`font-semibold truncate block ${email.reply_to && email.reply_to.domain !== email.sender.domain ? 'text-red-400' : 'text-slate-300'}`}>
              {email.reply_to ? email.reply_to.email : 'Same as sender'}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-black/30 border border-soc-border flex items-center justify-between">
            <div className="overflow-hidden">
              <span className="text-soc-muted block text-[10px] uppercase">SHA-256 Evidence Hash</span>
              <span className="text-cyan-400 text-[11px] truncate block" title={evidence.sha256_hash}>
                {evidence.sha256_hash.slice(0, 18)}...
              </span>
            </div>
            <button
              onClick={() => copyToClipboard(evidence.sha256_hash)}
              className="p-1.5 rounded hover:bg-slate-800 text-soc-muted hover:text-white"
              title="Copy full SHA-256 hash"
            >
              {copiedHash ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center gap-1.5 overflow-x-auto border-b border-soc-border pb-1">
        {tabs.map((t) => {
          const Icon = t.icon;
          const isActive = activeTab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-medium whitespace-nowrap transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                  : 'text-soc-muted hover:text-white hover:bg-soc-card'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span>{t.label}</span>
              {t.count !== undefined && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${isActive ? 'bg-cyan-500/20 text-cyan-200' : 'bg-slate-800 text-soc-muted'}`}>
                  {t.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* TAB CONTENT: Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Scorecard */}
            <div className="rounded-xl border border-soc-border bg-soc-card p-6 flex flex-col items-center justify-center text-center space-y-4">
              <div className={`relative h-32 w-32 rounded-full border-4 flex flex-col items-center justify-center ${scoreColor} shadow-[0_0_20px_rgba(0,0,0,0.5)]`}>
                <span className="text-3xl font-bold font-mono text-white">{threat.score}</span>
                <span className="text-[10px] font-mono text-soc-muted">/ 100</span>
              </div>
              <div className="space-y-1">
                <SeverityBadge severity={threat.severity} />
                <h3 className="font-mono font-bold text-sm text-white pt-2">{threat.classification}</h3>
                <p className="text-xs text-soc-muted max-w-xs">{threat.summary}</p>
              </div>
            </div>

            {/* Authentication Matrix */}
            <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-soc-muted">
                Authentication Signals
              </h3>
              <div className="space-y-2.5">
                <AuthBadge protocol="SPF Check" result={authentication.spf_result} />
                <AuthBadge protocol="DKIM Signature" result={authentication.dkim_result} />
                <AuthBadge protocol="DMARC Policy" result={authentication.dmarc_result} />
              </div>
              <p className="text-[11px] font-mono text-soc-muted">
                * Based on recorded authentication headers evaluated against sending infrastructure.
              </p>
            </div>

            {/* Quick Hops & Source IP */}
            <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3 font-mono text-xs">
              <h3 className="text-xs font-bold uppercase tracking-wider text-soc-muted">
                Origin Infrastructure
              </h3>
              <div className="p-3 rounded-lg bg-black/40 border border-soc-border space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-soc-muted">Probable Source IP:</span>
                  <span className="text-cyan-400 font-bold">{email.earliest_source_ip || 'None detected'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-soc-muted">Total Relay Hops:</span>
                  <span className="text-white">{relay_path.length} hops</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-soc-muted">Lookalike Domains:</span>
                  <span className={domains.some(d => d.lookalike_detected) ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                    {domains.filter(d => d.lookalike_detected).length} Detected
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-soc-muted">Attachments:</span>
                  <span className={attachments.some(a => a.is_suspicious) ? 'text-red-400 font-bold' : 'text-white'}>
                    {attachments.length} ({attachments.filter(a => a.is_suspicious).length} suspicious)
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Risk Factors List */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-cyan-400" />
              Explainable Risk Factors Breakdown
            </h3>
            <div className="divide-y divide-soc-border">
              {risk_factors.length === 0 ? (
                <p className="text-xs font-mono text-soc-muted py-4">No risk triggers identified. Communication appears legitimate.</p>
              ) : (
                risk_factors.map((factor, idx) => (
                  <div key={idx} className="py-3 flex items-start justify-between gap-4 font-mono">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-xs text-white">{factor.name}</span>
                        <SeverityBadge severity={factor.severity} size="sm" />
                      </div>
                      <p className="text-xs text-soc-muted">{factor.explanation}</p>
                    </div>
                    <span className="text-xs font-bold text-cyan-400 shrink-0 px-2 py-1 rounded bg-cyan-500/10 border border-cyan-500/20">
                      +{factor.points} pts
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: Header Forensics */}
      {activeTab === 'headers' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
              Identity & Header Consistency Findings
            </h3>
            <div className="space-y-3">
              {header_findings.map((f, idx) => (
                <div key={idx} className="p-4 rounded-lg bg-black/40 border border-soc-border space-y-2 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm">{f.message}</span>
                    <SeverityBadge severity={f.severity} size="sm" />
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800 text-soc-muted">
                    <b>Evidence:</b> {f.evidence}
                  </div>
                  <p className="text-soc-muted">{f.explanation}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Raw Headers Viewer */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Terminal className="h-4 w-4 text-cyan-400" />
              Raw Message Headers
            </h3>
            <pre className="p-4 rounded-lg bg-black text-[11px] font-mono text-slate-300 overflow-x-auto max-h-96 border border-soc-border">
              {JSON.stringify(email.raw_headers, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* TAB CONTENT: Authentication */}
      {activeTab === 'auth' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-5 rounded-xl border border-soc-border bg-soc-card space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-sm text-white">SPF Protocol</span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-black/50 border border-current text-cyan-400">
                  {authentication.spf_result}
                </span>
              </div>
              <p className="text-xs font-mono text-soc-muted">
                {authentication.spf_details || 'Sender Policy Framework verification.'}
              </p>
            </div>

            <div className="p-5 rounded-xl border border-soc-border bg-soc-card space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-sm text-white">DKIM Protocol</span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-black/50 border border-current text-cyan-400">
                  {authentication.dkim_result}
                </span>
              </div>
              <p className="text-xs font-mono text-soc-muted">
                {authentication.dkim_details || 'DomainKeys Identified Mail cryptographic signature.'}
              </p>
            </div>

            <div className="p-5 rounded-xl border border-soc-border bg-soc-card space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-sm text-white">DMARC Policy</span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-black/50 border border-current text-cyan-400">
                  {authentication.dmarc_result}
                </span>
              </div>
              <p className="text-xs font-mono text-soc-muted">
                {authentication.dmarc_details || 'Domain-based Message Authentication alignment policy.'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: Relay Path */}
      {activeTab === 'relay' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Chronological Received Transmission Hops
          </h3>
          <div className="space-y-4">
            {relay_path.map((hop) => (
              <div key={hop.hop_number} className="relative pl-6 border-l-2 border-cyan-500/40 space-y-1 font-mono text-xs">
                <div className="absolute -left-2 top-0 h-4 w-4 rounded-full bg-cyan-500 flex items-center justify-center text-[10px] font-bold text-slate-950">
                  {hop.hop_number}
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">
                    {hop.hop_number === 1 ? 'Hop 1 (Origin Sender Relay)' : `Relay Hop ${hop.hop_number}`}
                  </span>
                  <span className="text-soc-muted text-[11px]">{hop.timestamp || 'Unknown Time'}</span>
                </div>
                <p className="text-soc-muted">
                  <b>From:</b> {hop.from_host || 'N/A'} {hop.ip && <span className="text-cyan-400">[{hop.ip}]</span>}
                </p>
                <p className="text-soc-muted">
                  <b>By:</b> {hop.by_host || 'N/A'} {hop.protocol && `(via ${hop.protocol})`}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB CONTENT: URLs & Payloads */}
      {activeTab === 'urls' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
              Extracted Hyperlinks & Domain Inspection
            </h3>
            {urls.length === 0 ? (
              <p className="text-xs font-mono text-soc-muted">No external URLs detected in email body.</p>
            ) : (
              <div className="space-y-3 font-mono text-xs">
                {urls.map((u, idx) => (
                  <div key={idx} className="p-3.5 rounded-lg bg-black/40 border border-soc-border space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-cyan-400 font-bold break-all">{u.url}</span>
                      <SeverityBadge severity={u.risk_level} size="sm" />
                    </div>
                    <div className="text-soc-muted flex flex-wrap gap-4 pt-1 text-[11px]">
                      <span><b>Domain:</b> {u.domain}</span>
                      <span><b>Entropy:</b> {u.entropy}</span>
                      {u.context_text && <span><b>Anchor:</b> "{u.context_text}"</span>}
                      {u.has_ip_host && <span className="text-red-400">⚠️ IP Host</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT: Attachments */}
      {activeTab === 'attachments' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Preserved Attachments & Static Payload Analysis
          </h3>
          {attachments.length === 0 ? (
            <p className="text-xs font-mono text-soc-muted">No attachments included in this email.</p>
          ) : (
            <div className="space-y-3 font-mono text-xs">
              {attachments.map((att, idx) => (
                <div key={idx} className="p-4 rounded-lg bg-black/40 border border-soc-border space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm flex items-center gap-2">
                      <Paperclip className="h-4 w-4 text-cyan-400" />
                      {att.filename}
                    </span>
                    <SeverityBadge severity={att.is_suspicious ? 'CRITICAL' : 'LOW'} size="sm" />
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-soc-muted text-[11px]">
                    <div><b>Size:</b> {att.size_bytes} bytes</div>
                    <div><b>MIME:</b> {att.content_type}</div>
                    <div className="col-span-2"><b>SHA-256:</b> <span className="text-cyan-300">{att.sha256_hash}</span></div>
                  </div>
                  {att.is_suspicious && (
                    <div className="p-2 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-[11px]">
                      <b>Flagged:</b> {att.suspicion_reasons.join(' ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB CONTENT: Geo & ASN Map */}
      {activeTab === 'geo' && (
        <div className="space-y-6">
          <GeoMap ipList={ips} earliestSourceIp={email.earliest_source_ip} />

          <div className="rounded-xl border border-soc-border bg-soc-card p-5">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white mb-3">
              Network Infrastructure Table
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-black/40 text-soc-muted border-b border-soc-border">
                  <tr>
                    <th className="p-2.5">IP Address</th>
                    <th className="p-2.5">Location</th>
                    <th className="p-2.5">Organization / ISP</th>
                    <th className="p-2.5">ASN</th>
                    <th className="p-2.5">Routing Type</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border">
                  {ips.map((ipNode) => (
                    <tr key={ipNode.ip} className="hover:bg-soc-cardHover/50">
                      <td className="p-2.5 font-bold text-cyan-400">{ipNode.ip}</td>
                      <td className="p-2.5 text-white">{ipNode.city}, {ipNode.country}</td>
                      <td className="p-2.5 text-soc-muted">{ipNode.organization}</td>
                      <td className="p-2.5 text-soc-muted">{ipNode.asn}</td>
                      <td className="p-2.5">
                        {ipNode.is_proxy_vpn ? (
                          <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px]">Tor/VPN/Proxy</span>
                        ) : ipNode.is_hosting ? (
                          <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 text-[10px]">Hosting Provider</span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-soc-muted text-[10px]">Standard Network</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: IOC Registry */}
      {activeTab === 'iocs' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
                Preserved Indicators of Compromise (IOCs)
              </h3>
              <p className="text-xs text-soc-muted">Standardized forensic artifact table</p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-black/40 text-soc-muted border-b border-soc-border">
                <tr>
                  <th className="p-2.5">Type</th>
                  <th className="p-2.5">Indicator Value</th>
                  <th className="p-2.5">Source Context</th>
                  <th className="p-2.5">Risk Rating</th>
                  <th className="p-2.5 text-right">Copy</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {iocs.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-soc-cardHover/50">
                    <td className="p-2.5 font-bold text-cyan-400">{ioc.ioc_type}</td>
                    <td className="p-2.5 text-white max-w-xs break-all">{ioc.value}</td>
                    <td className="p-2.5 text-soc-muted">{ioc.source}</td>
                    <td className="p-2.5">
                      <SeverityBadge severity={ioc.risk} size="sm" />
                    </td>
                    <td className="p-2.5 text-right">
                      <button
                        onClick={() => copyToClipboard(ioc.value)}
                        className="p-1 rounded hover:bg-slate-800 text-soc-muted hover:text-white"
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT: Attack Graph */}
      {activeTab === 'graph' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-2">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
              Attack & Infrastructure Relationship Graph
            </h3>
            <p className="text-xs text-soc-muted">
              Interactive NetworkX / React Flow topology correlating Email root, Sender, Domains, IPs, ASNs, and URLs.
            </p>
          </div>
          <AttackGraph graphData={graph} />
        </div>
      )}

      {/* TAB CONTENT: Timeline */}
      {activeTab === 'timeline' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Investigation & Transmission Timeline
          </h3>
          <div className="space-y-4">
            {timeline.map((ev, idx) => (
              <div key={idx} className="relative pl-6 border-l-2 border-cyan-500/30 space-y-1 font-mono text-xs">
                <div className="absolute -left-1.5 top-0 h-3 w-3 rounded-full bg-cyan-400" />
                <span className="text-[10px] text-cyan-400 uppercase font-bold">{ev.event_type} &bull; {ev.timestamp}</span>
                <p className="text-white">{ev.description}</p>
                <span className="text-[11px] text-soc-muted">Source: {ev.source}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB CONTENT: Evidence Integrity */}
      {activeTab === 'evidence' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-6 space-y-5 font-mono">
          <div className="border-b border-soc-border pb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <KeyRound className="h-5 w-5 text-cyan-400" />
              Cryptographic Evidence Chain of Custody
            </h3>
            <p className="text-xs text-soc-muted mt-1">
              Immutable SHA-256 verification guaranteeing original raw email has not been modified.
            </p>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 rounded-lg bg-black/40 border border-soc-border space-y-1">
              <span className="text-soc-muted uppercase text-[10px]">Preserved SHA-256 Checksum</span>
              <span className="text-cyan-400 font-bold block break-all">{evidence.sha256_hash}</span>
            </div>

            <div className="p-3 rounded-lg bg-black/40 border border-soc-border space-y-1">
              <span className="text-soc-muted uppercase text-[10px]">MD5 Checksum</span>
              <span className="text-slate-300 font-bold block break-all">{evidence.md5_hash}</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-black/40 border border-soc-border">
                <span className="text-soc-muted uppercase text-[10px]">Evidence ID</span>
                <span className="text-white font-bold block">{evidence.evidence_id}</span>
              </div>
              <div className="p-3 rounded-lg bg-black/40 border border-soc-border">
                <span className="text-soc-muted uppercase text-[10px]">Timestamp</span>
                <span className="text-white font-bold block">{evidence.preservation_timestamp}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Analysis;
