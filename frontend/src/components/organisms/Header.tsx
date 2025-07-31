'use client';

import { Menu, Settings } from 'lucide-react';

interface HeaderProps {
  onNavigationClick: () => void;
  onSettingsClick: () => void;
}

export function Header({ onNavigationClick, onSettingsClick }: HeaderProps) {
  return (
    <header className="bg-gray-800/95 backdrop-blur-sm border-b border-gray-700/50 px-6 py-4 sticky top-0 z-40">
      <div className="flex items-center justify-between max-w-7xl mx-auto">
        {/* Hamburger Menu */}
        <button
          onClick={onNavigationClick}
          className="p-3 rounded-xl hover:bg-gray-700/50 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800 group"
          aria-label="Open navigation menu"
        >
          <Menu className="w-6 h-6 text-gray-300 group-hover:text-white transition-colors duration-200" />
        </button>

        {/* Centered Title */}
        <h1 className="text-2xl font-bold text-white tracking-tight">
          Bug Hunting Framework
        </h1>

        {/* Settings Icon */}
        <button
          onClick={onSettingsClick}
          className="p-3 rounded-xl hover:bg-gray-700/50 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800 group"
          aria-label="Open settings"
        >
          <Settings className="w-6 h-6 text-gray-300 group-hover:text-white transition-colors duration-200" />
        </button>
      </div>
    </header>
  );
} 