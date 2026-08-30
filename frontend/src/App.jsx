import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/layout/Navbar';
import Dashboard from './pages/Dashboard';
import Upload from './pages/Upload';
import Analysis from './pages/Analysis';
import Cases from './pages/Cases';

export function App() {
  return (
    <Router>
      <div className="min-h-screen flex flex-col bg-soc-bg text-soc-text font-sans antialiased">
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/analysis" element={<Analysis />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <footer className="border-t border-soc-border bg-soc-card/50 py-4 text-center text-xs font-mono text-soc-muted">
          AnveshakX — AI-ready Email Threat Detection, Geolocation & Forensic Intelligence Platform (SIH Phase 1 Prototype)
        </footer>
      </div>
    </Router>
  );
}

export default App;
