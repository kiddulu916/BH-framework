'use client';

import React from 'react';
import { performanceMonitor, PerformanceMetrics } from '@/lib/utils/performance';

export function PerformanceMonitorComponent() {
  const [metrics, setMetrics] = React.useState<PerformanceMetrics>(() => performanceMonitor.getMetrics());
  // Avoid hydration mismatch – only render after component is mounted in browser
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
    const interval = setInterval(() => {
      setMetrics(performanceMonitor.getMetrics());
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  if (process.env.NODE_ENV !== 'development' || !mounted) {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 bg-zinc-800 border border-zinc-700 rounded-lg p-4 text-xs font-mono z-50" suppressHydrationWarning>
      <div className="text-gray-300 mb-2">Performance Metrics</div>
      <div className="space-y-1 text-gray-400">
        <div suppressHydrationWarning>FCP: {metrics.fcp?.toFixed(0) || 'N/A'}ms</div>
        <div suppressHydrationWarning>LCP: {metrics.lcp?.toFixed(0) || 'N/A'}ms</div>
        <div suppressHydrationWarning>FID: {metrics.fid?.toFixed(0) || 'N/A'}ms</div>
        <div suppressHydrationWarning>CLS: {metrics.cls?.toFixed(3) || 'N/A'}</div>
        <div suppressHydrationWarning>TTFB: {metrics.ttfb?.toFixed(0) || 'N/A'}ms</div>
      </div>
    </div>
  );
} 