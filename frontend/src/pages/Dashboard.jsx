import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, AlertTriangle, CheckCircle, Database, FileSearch, Server, Radio, UploadCloud } from 'lucide-react';
import api from '../services/api';
import StatCard from '../components/dashboard/StatCard';
import ThreatDistributionChart from '../components/dashboard/ThreatDistributionChart';
import RecentCasesTable from '../components/dashboard/RecentCasesTable';

export const Dashboard = () => {
  const [cases, setCases] = useState([]);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const [casesRes, healthRes] = await Promise.all([
          api.listCases({ limit: 20 }),
          api.getHealth()
        ]);
        setCases(casesRes.cases || []);
        setHealth(healthRes);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const totalCases = cases.length;
  const criticalCases = cases.filter(c => (c.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCases = cases.filter(c => (c.severity || '').toUpperCase() === 'HIGH').length;
  const mediumCases = cases.filter(c => (c.severity || '').toUpperCase() === 'MEDIUM').length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-5">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            <Radio className="h-6 w-6 text-cyan-400 animate-pulse" />
            Security Operations Center (SOC)
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            AnveshakX Deterministic Email Threat Detection & Forensic Investigation Platform
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/upload"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition-all shadow-[0_0_15px_rgba(6,182,212,0.4)]"
          >
            <UploadCloud className="h-4 w-4" />
            Analyze New Email (.eml)
          </Link>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Investigations"
          value={totalCases}
          subtitle="Processed forensic artifacts"
          icon={Database}
          color="cyan"
        />
        <StatCard
          title="Critical Threats"
          value={criticalCases}
          subtitle="BEC & lookalike intrusions"
          icon={ShieldAlert}
          color="red"
          badge="High Priority"
        />
        <StatCard
          title="High Risk Incidents"
          value={highCases}
          subtitle="Phishing & payload attacks"
          icon={AlertTriangle}
          color="orange"
        />
        <StatCard
          title="Medium / Benign"
          value={mediumCases + (totalCases - criticalCases - highCases - mediumCases)}
          subtitle="Anomalies & valid emails"
          icon={CheckCircle}
          color="emerald"
        />
      </div>

      {/* Charts & System Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <ThreatDistributionChart cases={cases} />
        </div>

        <div className="lg:col-span-2">
          <RecentCasesTable cases={cases} loading={loading} />
        </div>
      </div>

      {/* Quick Demonstration Links Banner */}
      <div className="rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-500/10 via-soc-card to-transparent p-5">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400 px-2 py-0.5 rounded bg-cyan-500/20 border border-cyan-500/30">
              SIH Screening Demo Mode
            </span>
            <h3 className="text-sm font-mono font-bold text-white mt-1.5">
              Ready for Instant Offline Evaluation
            </h3>
            <p className="text-xs text-soc-muted max-w-xl">
              AnveshakX includes synthetic forensic attack vectors (Executive BEC, Credential Phishing, Double Extension Malware) that execute in seconds without external API dependencies.
            </p>
          </div>
          <Link
            to="/upload"
            className="px-4 py-2 rounded-lg bg-soc-card border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/20 font-mono text-xs font-semibold whitespace-nowrap transition-colors"
          >
            Launch Demo Vectors &rarr;
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
