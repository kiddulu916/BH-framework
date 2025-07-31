'use client';

import { Play } from 'lucide-react';

export function StartButton() {
  const handleStart = () => {
    // TODO: Implement start functionality
    console.log('Starting bug hunting framework...');
  };

  return (
    <button
      onClick={handleStart}
      className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white px-10 py-4 rounded-2xl font-semibold transition-all duration-300 focus:outline-none focus:ring-4 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 flex items-center space-x-3 shadow-2xl hover:shadow-blue-500/25 hover:scale-105 active:scale-95"
    >
      <Play className="w-6 h-6" />
      <span className="text-lg">Start</span>
    </button>
  );
} 