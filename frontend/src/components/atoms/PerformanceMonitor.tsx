'use client';

import React from 'react';
import { performanceMonitor, PerformanceMetrics } from '@/lib/utils/performance';

export function PerformanceMonitorComponent() {
  const [metrics, setMetrics] = React.useState<PerformanceMetrics>(performanceMonitor.getMetrics());

  React.useEffect(() => {
    const interval = setInterval(() => {
      setMetrics(performanceMonitor.getMetrics());
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  if (process.env.NODE_ENV !== 'development') {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 bg-zinc-800 border border-zinc-700 rounded-lg p-4 text-xs font-mono z-50">
      <div className="text-gray-300 mb-2">Performance Metrics</div>
      <div className="space-y-1 text-gray-400">
        <div>FCP: {metrics.fcp?.toFixed(0) || 'N/A'}ms</div>
        <div>LCP: {metrics.lcp?.toFixed(0) || 'N/A'}ms</div>
        <div>FID: {metrics.fid?.toFixed(0) || 'N/A'}ms</div>
        <div>CLS: {metrics.cls?.toFixed(3) || 'N/A'}</div>
        <div>TTFB: {metrics.ttfb?.toFixed(0) || 'N/A'}ms</div>
      </div>
    </div>
  );
} 