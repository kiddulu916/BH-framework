'use client';

import { useState, useEffect } from 'react';
import { Header } from '@/components/organisms/Header';
import { OverlayManager } from '@/components/organisms/OverlayManager';
import { 
  getPassiveReconResults, 
  getPassiveReconStatus, 
  startPassiveRecon,
  StageResult,
  StageStatus
} from '@/lib/api/stages';

interface PassiveReconPageProps {
  target?: any;
}

export function PassiveReconPage({ target }: PassiveReconPageProps) {
  const [activeOverlay, setActiveOverlay] = useState<'navigation' | 'settings' | null>(null);
  const [results, setResults] = useState<StageResult[]>([]);
  const [status, setStatus] = useState<StageStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedTools, setSelectedTools] = useState<string[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);

  const availableTools = [
    'Sublist3r', 'Amass', 'Subfinder', 'Assetfinder', 'Gau', 'Waybackurls',
    'Httpx', 'Nuclei', 'Naabu', 'Katana', 'Feroxbuster', 'Gobuster',
    'LinkFinder', 'GetJS', 'EyeWitness', 'EyeBaller', 'WebAnalyze',
    'WhatWeb', 'FingerprintX', 'Arjun', 'MassDNS', 'PureDNS', 'FFuf',
    'WAFW00F', 'CloudFail', 'CloudEnum', 'S3Enum'
  ];

  const fetchData = async () => {
    if (!target?.id) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const [resultsData, statusData] = await Promise.allSettled([
        getPassiveReconResults(target.id),
        getPassiveReconStatus(target.id)
      ]);

      if (resultsData.status === 'fulfilled') {
        setResults(resultsData.value);
      }

      if (statusData.status === 'fulfilled') {
        setStatus(statusData.value);
      }
    } catch (err) {
      console.error('Failed to fetch passive recon data:', err);
      setError('Failed to load passive recon data');
    } finally {
      setLoading(false);
    }
  };

  const handleStartExecution = async () => {
    if (!target?.id) return;
    
    try {
      setIsExecuting(true);
      setError(null);
      
      const request = {
        target_id: target.id,
        stage_name: 'passive-recon',
        tools: selectedTools.length > 0 ? selectedTools : undefined,
        options: {}
      };

      const result = await startPassiveRecon(request);
      console.log('Started passive recon:', result);
      
      // Refresh data after starting
      setTimeout(fetchData, 1000);
    } catch (err) {
      console.error('Failed to start passive recon:', err);
      setError('Failed to start passive recon');
    } finally {
      setIsExecuting(false);
    }
  };

  const handleToolToggle = (tool: string) => {
    setSelectedTools(prev => 
      prev.includes(tool) 
        ? prev.filter(t => t !== tool)
        : [...prev, tool]
    );
  };

  const getToolStatus = (toolName: string) => {
    const result = results.find(r => r.tool_name === toolName);
    if (!result) return { status: 'not_run', success: false };
    
    return {
      status: result.data?.success ? 'completed' : 'failed',
      success: result.data?.success || false,
      data: result.data
    };
  };

  const getProgressPercentage = () => {
    if (!status) return 0;
    if (status.total_tools === 0) return 0;
    return Math.round((status.completed_tools / status.total_tools) * 100);
  };

  const getStatusColor = () => {
    if (status?.status === 'completed') return 'bg-green-500';
    if (status?.status === 'failed') return 'bg-red-500';
    if (status?.status === 'running') return 'bg-blue-500';
    return 'bg-gray-500';
  };

  useEffect(() => {
    fetchData();
    
    // Poll for updates every 5 seconds
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [target?.id]);

  if (!target) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">No Target Selected</h1>
          <p className="text-gray-400">Please select a target to view passive reconnaissance results.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <OverlayManager activeOverlay={activeOverlay} setActiveOverlay={setActiveOverlay}>
        <Header 
          onNavigationClick={() => setActiveOverlay('navigation')}
          onSettingsClick={() => setActiveOverlay('settings')}
        />
        
        <main className="container mx-auto px-6 py-8 space-y-8">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white">Passive Reconnaissance</h1>
              <p className="text-gray-400 mt-2">Target: {target.target || target.domain}</p>
            </div>
            <button
              onClick={() => window.history.back()}
              className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Back to Dashboard
            </button>
          </div>

          {/* Error message */}
          {error && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-4 text-red-300">
              {error}
            </div>
          )}

          {/* Status Overview */}
          {status && (
            <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
              <h2 className="text-xl font-semibold text-white mb-4">Execution Status</h2>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                <div className="text-center">
                  <div className={`w-4 h-4 rounded-full ${getStatusColor()} mx-auto mb-2`}></div>
                  <div className="text-sm text-gray-400">{status.status}</div>
                </div>
                <div className="text-center">
                  <div className="text-blue-400 font-semibold text-xl">{status.total_tools}</div>
                  <div className="text-sm text-gray-400">Total Tools</div>
                </div>
                <div className="text-center">
                  <div className="text-green-400 font-semibold text-xl">{status.completed_tools}</div>
                  <div className="text-sm text-gray-400">Completed</div>
                </div>
                <div className="text-center">
                  <div className="text-red-400 font-semibold text-xl">{status.failed_tools}</div>
                  <div className="text-sm text-gray-400">Failed</div>
                </div>
              </div>
              
              {/* Progress bar */}
              <div className="mb-2">
                <div className="flex justify-between text-sm text-gray-400 mb-1">
                  <span>Progress</span>
                  <span>{getProgressPercentage()}%</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-3">
                  <div 
                    className={`h-3 rounded-full transition-all duration-300 ${getStatusColor()}`}
                    style={{ width: `${getProgressPercentage()}%` }}
                  ></div>
                </div>
              </div>
            </div>
          )}

          {/* Tool Selection and Execution */}
          <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
            <h2 className="text-xl font-semibold text-white mb-4">Tool Selection</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
              {availableTools.map(tool => (
                <button
                  key={tool}
                  onClick={() => handleToolToggle(tool)}
                  className={`p-3 rounded-lg border transition-all ${
                    selectedTools.includes(tool)
                      ? 'bg-blue-600 border-blue-500 text-white'
                      : 'bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  <div className="text-xs font-medium">{tool}</div>
                  <div className={`text-xs mt-1 ${
                    getToolStatus(tool).status === 'completed' ? 'text-green-400' :
                    getToolStatus(tool).status === 'failed' ? 'text-red-400' :
                    'text-gray-500'
                  }`}>
                    {getToolStatus(tool).status}
                  </div>
                </button>
              ))}
            </div>
            
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-400">
                {selectedTools.length} of {availableTools.length} tools selected
              </div>
              <button
                onClick={handleStartExecution}
                disabled={isExecuting || status?.status === 'running'}
                className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-6 py-3 rounded-lg font-medium transition-colors"
              >
                {isExecuting || status?.status === 'running' ? 'Running...' : 'Start Passive Recon'}
              </button>
            </div>
          </div>

          {/* Results */}
          <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
            <h2 className="text-xl font-semibold text-white mb-4">Results</h2>
            {loading ? (
              <div className="text-center py-8">
                <div className="text-gray-400">Loading results...</div>
              </div>
            ) : results.length === 0 ? (
              <div className="text-center py-8">
                <div className="text-gray-400">No results available. Start passive reconnaissance to see results.</div>
              </div>
            ) : (
              <div className="space-y-4">
                {results.map((result) => (
                  <div key={result.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-white">{result.tool_name}</h3>
                      <div className={`px-2 py-1 rounded text-xs font-medium ${
                        result.data?.success ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'
                      }`}>
                        {result.data?.success ? 'Success' : 'Failed'}
                      </div>
                    </div>
                    
                    {result.data && (
                      <div className="text-sm text-gray-300">
                        <pre className="bg-gray-900 p-3 rounded overflow-x-auto text-xs">
                          {JSON.stringify(result.data, null, 2)}
                        </pre>
                      </div>
                    )}
                    
                    <div className="text-xs text-gray-500 mt-2">
                      Executed: {new Date(result.created_at).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </main>
      </OverlayManager>
    </div>
  );
} 