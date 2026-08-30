import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FolderGit2, Search, Filter, Trash2, ExternalLink, RefreshCw, FileText } from 'lucide-react';
import api from '../services/api';
import SeverityBadge from '../components/common/SeverityBadge';

export const Cases = () => {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const fetchCases = async () => {
    try {
      setLoading(true);
      const params = {};
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      const res = await api.listCases(params);
      setCases(res.cases || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, [severityFilter]);

  const handleDelete = async (caseId, e) => {
    e.preventDefault();
    if (window.confirm(`Are you sure you want to delete case ${caseId}?`)) {
      try {
        await api.deleteCase(caseId);
        setCases(cases.filter(c => c.id !== caseId));
      } catch (err) {
        console.error(err);
      }
    }
  };

  const filteredCases = cases.filter(c => {
    const term = search.toLowerCase();
    return c.id.toLowerCase().includes(term) || c.filename.toLowerCase().includes(term) || (c.classification || '').toLowerCase().includes(term);
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-5">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            <FolderGit2 className="h-6 w-6 text-cyan-400" />
            Case Investigation Registry
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Search, filter, and review stored email forensic investigation records
          </p>
        </div>

        <button
          onClick={fetchCases}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-soc-card hover:bg-soc-cardHover border border-soc-border text-xs font-mono text-soc-muted hover:text-white transition-colors"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Search */}
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-soc-muted" />
          <input
            type="text"
            placeholder="Search by Case ID, file, or class..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-soc-card border border-soc-border rounded-lg text-xs font-mono text-white placeholder-soc-muted focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Severity Filter Buttons */}
        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                severityFilter === sev
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-soc-card text-soc-muted hover:text-white border border-soc-border'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Cases Table */}
      <div className="rounded-xl border border-soc-border bg-soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-black/40 text-soc-muted uppercase border-b border-soc-border">
              <tr>
                <th className="px-4 py-3">Case ID</th>
                <th className="px-4 py-3">Filename</th>
                <th className="px-4 py-3">Threat Score</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Classification</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {loading ? (
                <tr>
                  <td colSpan="7" className="text-center py-12 text-soc-muted">
                    Loading cases...
                  </td>
                </tr>
              ) : filteredCases.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center py-12 text-soc-muted">
                    No cases match your search criteria.
                  </td>
                </tr>
              ) : (
                filteredCases.map((c) => (
                  <tr key={c.id} className="hover:bg-soc-cardHover/40 transition-colors">
                    <td className="px-4 py-3 font-bold text-cyan-400">
                      <Link to={`/analysis?case_id=${c.id}`} className="hover:underline">
                        {c.id}
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-white max-w-[200px] truncate">
                      {c.filename}
                    </td>
                    <td className="px-4 py-3 font-bold">
                      <span className={c.threat_score >= 80 ? 'text-red-400' : c.threat_score >= 60 ? 'text-orange-400' : c.threat_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                        {c.threat_score} / 100
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={c.severity} size="sm" />
                    </td>
                    <td className="px-4 py-3 text-soc-muted max-w-[180px] truncate">
                      {c.classification}
                    </td>
                    <td className="px-4 py-3 text-soc-muted">
                      {new Date(c.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      <Link
                        to={`/analysis?case_id=${c.id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-[11px]"
                      >
                        <FileText className="h-3 w-3" />
                        Inspect
                      </Link>
                      <button
                        onClick={(e) => handleDelete(c.id, e)}
                        className="p-1 rounded hover:bg-red-500/20 text-soc-muted hover:text-red-400 text-[11px]"
                        title="Delete Case"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Cases;
