import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Radio, Activity, FileSearch, FolderGit2, FileText } from 'lucide-react';

export const Navbar = () => {
  const location = useLocation();

  const navLinks = [
    { name: 'SOC Dashboard', path: '/', icon: Activity },
    { name: 'Analyze Email', path: '/upload', icon: FileSearch },
    { name: 'Case Registry', path: '/cases', icon: FolderGit2 },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-soc-border bg-soc-card/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative flex items-center justify-center h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 group-hover:border-cyan-400 transition-colors shadow-[0_0_15px_rgba(6,182,212,0.25)]">
              <Shield className="h-5 w-5" />
              <span className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-cyan-400 radar-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-lg tracking-wider text-white">ANVESHAK<span className="text-cyan-400">X</span></span>
                {/* <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">Phase 1</span> */}
              </div>
              <p className="text-[11px] text-soc-muted truncate hidden sm:block">Email Threat Detection & Forensics</p>
            </div>
          </Link>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            {navLinks.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                      : 'text-soc-muted hover:text-white hover:bg-soc-cardHover'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span className="hidden md:inline">{item.name}</span>
                </Link>
              );
            })}
          </nav>

          {/* Status Indicator */}
          <div className="hidden lg:flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-3 py-1.5 rounded-full">
            <Radio className="h-3.5 w-3.5 animate-pulse" />
            <span>CORE FORENSICS: ACTIVE</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
