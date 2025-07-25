import React from 'react';

// Performance monitoring utilities

export interface PerformanceMetrics {
  fcp: number | null; // First Contentful Paint
  lcp: number | null; // Largest Contentful Paint
  fid: number | null; // First Input Delay
  cls: number | null; // Cumulative Layout Shift
  ttfb: number | null; // Time to First Byte
}

export interface CustomMetric {
  name: string;
  value: number;
  timestamp: number;
  metadata?: Record<string, any>;
}

// Type definition for LayoutShift entries
interface LayoutShift extends PerformanceEntry {
  value: number;
  hadRecentInput: boolean;
  lastInputTime: number;
  sources: Array<any>;
}

class PerformanceMonitor {
  private metrics: PerformanceMetrics = {
    fcp: null,
    lcp: null,
    fid: null,
    cls: null,
    ttfb: null,
  };

  private customMetrics: CustomMetric[] = [];
  private observers: Map<string, PerformanceObserver> = new Map();

  constructor() {
    this.initCoreWebVitals();
    this.initCustomMetrics();
  }

  private initCoreWebVitals() {
    if (typeof window === 'undefined') return;

    // First Contentful Paint
    if ('PerformanceObserver' in window) {
      try {
        const fcpObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const fcpEntry = entries.find(entry => entry.name === 'first-contentful-paint');
          if (fcpEntry) {
            this.metrics.fcp = fcpEntry.startTime;
            this.logMetric('FCP', fcpEntry.startTime);
          }
        });
        fcpObserver.observe({ entryTypes: ['paint'] });
        this.observers.set('fcp', fcpObserver);
      } catch (error) {
        console.warn('FCP observer failed:', error);
      }

      // Largest Contentful Paint
      try {
        const lcpObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const lastEntry = entries[entries.length - 1];
          if (lastEntry) {
            this.metrics.lcp = lastEntry.startTime;
            this.logMetric('LCP', lastEntry.startTime);
          }
        });
        lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] });
        this.observers.set('lcp', lcpObserver);
      } catch (error) {
        console.warn('LCP observer failed:', error);
      }

      // First Input Delay
      try {
        const fidObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const fidEntry = entries[0] as PerformanceEventTiming;
          if (fidEntry && 'processingStart' in fidEntry) {
            this.metrics.fid = fidEntry.processingStart - fidEntry.startTime;
            this.logMetric('FID', this.metrics.fid);
          }
        });
        fidObserver.observe({ entryTypes: ['first-input'] });
        this.observers.set('fid', fidObserver);
      } catch (error) {
        console.warn('FID observer failed:', error);
      }

      // Cumulative Layout Shift
      try {
        const clsObserver = new PerformanceObserver((list) => {
          let clsValue = 0;
          for (const entry of list.getEntries()) {
            if (entry.entryType === 'layout-shift') {
              const lsEntry = entry as LayoutShift;
              if (!lsEntry.hadRecentInput) {
                clsValue += lsEntry.value;
              }
            }
          }
          this.metrics.cls = clsValue;
          this.logMetric('CLS', clsValue);
        });
        clsObserver.observe({ entryTypes: ['layout-shift'] });
        this.observers.set('cls', clsObserver);
      } catch (error) {
        console.warn('CLS observer failed:', error);
      }
    }

    // Time to First Byte
    if ('performance' in window) {
      const navigationEntry = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      if (navigationEntry) {
        this.metrics.ttfb = navigationEntry.responseStart - navigationEntry.requestStart;
        this.logMetric('TTFB', this.metrics.ttfb);
      }
    }
  }

  private initCustomMetrics() {
    // Monitor component render times
    if (typeof window !== 'undefined') {
      console.log('Performance monitoring initialized (Docker container)');
      
      // Add container-specific metrics
      this.addCustomMetric('container_environment', 1, { 
        environment: 'docker',
        timestamp: Date.now()
      });
    }
  }

  private logMetric(name: string, value: number) {
    const metric: CustomMetric = {
      name,
      value,
      timestamp: Date.now(),
    };

    this.customMetrics.push(metric);

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`📊 ${name}:`, value.toFixed(2));
    }

    // Send to monitoring service in production
    if (process.env.NODE_ENV === 'production') {
      this.sendToMonitoringService(metric);
    }
  }

  private sendToMonitoringService(metric: CustomMetric) {
    // TODO: Send to monitoring service (Google Analytics, Sentry, etc.)
    // For Docker containers, consider sending to a centralized logging service
    // Example implementation:
    // gtag('event', 'performance_metric', {
    //   metric_name: metric.name,
    //   metric_value: metric.value,
    //   timestamp: metric.timestamp,
    //   container_id: process.env.HOSTNAME || 'unknown',
    // });
  }

  // Public API
  public getMetrics(): PerformanceMetrics {
    return { ...this.metrics };
  }

  public getCustomMetrics(): CustomMetric[] {
    return [...this.customMetrics];
  }

  public addCustomMetric(name: string, value: number, metadata?: Record<string, any>) {
    const metric: CustomMetric = {
      name,
      value,
      timestamp: Date.now(),
      metadata: {
        ...metadata,
        container_id: process.env.HOSTNAME || 'unknown',
        environment: process.env.NODE_ENV || 'development',
      },
    };
    this.customMetrics.push(metric);
    this.logMetric(name, value);
  }

  public measureAsync<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const startTime = performance.now();
    return fn().finally(() => {
      const duration = performance.now() - startTime;
      this.addCustomMetric(name, duration);
    });
  }

  public measureSync<T>(name: string, fn: () => T): T {
    const startTime = performance.now();
    try {
      const result = fn();
      const duration = performance.now() - startTime;
      this.addCustomMetric(name, duration);
      return result;
    } catch (error) {
      const duration = performance.now() - startTime;
      this.addCustomMetric(`${name}_error`, duration, { error: (error as Error).message });
      throw error;
    }
  }

  public disconnect() {
    this.observers.forEach(observer => observer.disconnect());
    this.observers.clear();
  }
}

// Create singleton instance
export const performanceMonitor = new PerformanceMonitor();

// React hook for measuring component render time
export function usePerformanceMeasure(name: string) {
  const startTime = React.useRef(performance.now());

  React.useEffect(() => {
    const duration = performance.now() - startTime.current;
    performanceMonitor.addCustomMetric(`${name}_render`, duration);
  });

  return {
    measureAsync: <T>(fn: () => Promise<T>) => performanceMonitor.measureAsync(`${name}_async`, fn),
    measureSync: <T>(fn: () => T) => performanceMonitor.measureSync(`${name}_sync`, fn),
  };
} 