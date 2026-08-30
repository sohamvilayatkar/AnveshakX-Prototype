import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, FileCode, CheckCircle, AlertTriangle, ShieldCheck, Zap, ArrowRight, Loader2 } from 'lucide-react';
import api from '../services/api';

export const Upload = () => {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [statusMsg, setStatusMsg] = useState('');

  const demoSamples = [
    {
      id: 'bec',
      title: 'Business Email Compromise (CEO Fraud)',
      vector: 'Executive Impersonation + Wire Transfer',
      desc: 'David Miller (CEO) impersonation with suspicious Reply-To redirect and urgent acquisition wire request.',
      threatLevel: 'CRITICAL',
      color: 'border-red-500/30 hover:border-red-500/60 bg-red-500/5'
    },
    {
      id: 'phishing',
      title: 'Credential Harvesting Phishing',
      vector: 'Account Suspension Urgency + Lookalike URL',
      desc: 'Banking suspension alert using lookalike domain (sbi-secure-portal-verify.xyz) with credential harvest links.',
      threatLevel: 'HIGH',
      color: 'border-orange-500/30 hover:border-orange-500/60 bg-orange-500/5'
    },
    {
      id: 'impersonation',
      title: 'Brand Impersonation & Dangerous Attachment',
      vector: 'Microsoft 365 Pretext + Double Extension Malware',
      desc: 'Past due invoice notice with attached double extension executable (invoice_overdue_scan.pdf.exe).',
      threatLevel: 'CRITICAL',
      color: 'border-purple-500/30 hover:border-purple-500/60 bg-purple-500/5'
    },
    {
      id: 'legitimate',
      title: 'Legitimate Corporate Communication',
      vector: 'Valid SPF, DKIM, DMARC + Matching Relay Hops',
      desc: 'Sprint planning review from Alice Roberts with matching domain alignment and valid DKIM/SPF headers.',
      threatLevel: 'BENIGN',
      color: 'border-emerald-500/30 hover:border-emerald-500/60 bg-emerald-500/5'
    }
  ];

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    if (selected) {
      setFile(selected);
      setError(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setError('Please select an .eml email file to upload.');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setStatusMsg('Preserving cryptographic evidence (SHA-256)...');
      
      const result = await api.uploadEmail(file, (progressEvent) => {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setProgress(percent);
      });

      setStatusMsg('Parsing headers, relay path, and threat rules...');
      // Pass data via sessionStorage or state and navigate
      sessionStorage.setItem('current_analysis', JSON.stringify(result));
      navigate(`/analysis?case_id=${result.case.id}`);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to upload and analyze email file.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadDemo = async (sampleId) => {
    try {
      setLoading(true);
      setError(null);
      setStatusMsg(`Loading synthetic vector: ${sampleId.toUpperCase()}...`);
      
      const result = await api.loadSampleEmail(sampleId);
      sessionStorage.setItem('current_analysis', JSON.stringify(result));
      navigate(`/analysis?case_id=${result.case.id}`);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || `Failed to load demo sample ${sampleId}.`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Title */}
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold font-mono tracking-tight text-white">
          Email Forensic Ingestion
        </h1>
        <p className="text-sm text-soc-muted max-w-xl mx-auto">
          Upload a raw .eml file to preserve evidence integrity, reconstruct relay paths, verify authentication signals, and compute an explainable threat assessment.
        </p>
      </div>

      {/* Upload Box */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        className={`rounded-2xl border-2 border-dashed p-8 text-center transition-all ${
          file
            ? 'border-cyan-500/50 bg-cyan-500/5'
            : 'border-soc-border hover:border-soc-borderLight bg-soc-card'
        }`}
      >
        <input
          type="file"
          id="email-file-input"
          accept=".eml,.msg,.txt"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-4">
          <div className="p-4 rounded-2xl bg-black/40 border border-soc-border text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.2)]">
            <UploadCloud className="h-10 w-10" />
          </div>

          {file ? (
            <div className="space-y-1">
              <p className="font-mono text-sm font-bold text-white flex items-center justify-center gap-2">
                <FileCode className="h-4 w-4 text-cyan-400" />
                {file.name}
              </p>
              <p className="text-xs font-mono text-soc-muted">
                {(file.size / 1024).toFixed(2)} KB &bull; MIME: {file.type || 'message/rfc822'}
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <p className="font-mono text-sm font-semibold text-white">
                Drag and drop your raw <span className="text-cyan-400">.eml</span> email here
              </p>
              <p className="text-xs text-soc-muted">
                or click to browse your local filesystem (Max 25 MB)
              </p>
            </div>
          )}

          <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
            <label
              htmlFor="email-file-input"
              className="cursor-pointer px-4 py-2 rounded-lg bg-soc-cardHover hover:bg-slate-700 text-white font-mono text-xs transition-colors border border-soc-border"
            >
              {file ? 'Choose Different File' : 'Select .EML File'}
            </label>

            {file && (
              <button
                onClick={handleUpload}
                disabled={loading}
                className="px-6 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition-all shadow-[0_0_15px_rgba(6,182,212,0.4)] flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {statusMsg || 'Processing...'}
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4" />
                    Start Forensic Analysis
                  </>
                )}
              </button>
            )}
          </div>

          {loading && (
            <div className="w-full max-w-xs space-y-2 mt-4">
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-cyan-400 transition-all duration-300"
                  style={{ width: `${progress > 0 ? progress : 60}%` }}
                />
              </div>
              <p className="text-[11px] font-mono text-cyan-400 animate-pulse">{statusMsg}</p>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 font-mono text-xs flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>
      </div>

      {/* Fast Demo Selection Grid */}
      <div className="space-y-4 pt-4 border-t border-soc-border">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-mono font-bold text-white flex items-center gap-2">
              <Zap className="h-4 w-4 text-cyan-400" />
              1-Click Smart India Hackathon (SIH) Demo Vectors
            </h2>
            <p className="text-xs text-soc-muted">
              Pre-built forensic scenarios demonstrating diverse email threat categories
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {demoSamples.map((demo) => (
            <button
              key={demo.id}
              onClick={() => handleLoadDemo(demo.id)}
              disabled={loading}
              className={`p-4 rounded-xl border text-left transition-all hover:scale-[1.01] flex flex-col justify-between group ${demo.color}`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-black/40 border border-current">
                    {demo.threatLevel}
                  </span>
                  <span className="text-xs font-mono text-soc-muted group-hover:text-cyan-400 flex items-center gap-1 transition-colors">
                    Load Sample <ArrowRight className="h-3 w-3" />
                  </span>
                </div>
                <h3 className="font-mono font-bold text-sm text-white group-hover:text-cyan-300 transition-colors">
                  {demo.title}
                </h3>
                <p className="text-[11px] font-mono text-cyan-400/90 font-medium">
                  Vector: {demo.vector}
                </p>
                <p className="text-xs text-soc-muted leading-relaxed">
                  {demo.desc}
                </p>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Upload;
