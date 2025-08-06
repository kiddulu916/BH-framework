'use client';

import { useState, useEffect } from 'react';
import { Header } from '@/components/organisms/Header';
import { TargetProfileCard } from '@/components/organisms/TargetProfileCard';
import { StageCard } from '@/components/organisms/StageCard';
import { StartButton } from '@/components/atoms/StartButton';
import { OverlayManager } from '@/components/organisms/OverlayManager';
import { 
  getStageSummary, 
  startPassiveRecon, 
  startActiveRecon,
  getPassiveReconStatus,
  getActiveReconStatus,
  StageStatus,
  StageResult
} from '@/lib/api/stages';
import { getTargets, updateTarget } from '@/lib/api/targets';
import { TargetStatus } from '@/types/target';

export function DashboardPage({ target }: { target?: any }) {
  const [activeOverlay, setActiveOverlay] = useState<'navigation' | 'settings' | null>(null);
  const [stageData, setStageData] = useState<{
    passive_recon: { results: StageResult[]; count: number };
    active_recon: { results: StageResult[]; count: number };
    recursive_recon: { results: any; has_data: boolean };
  } | null>(null);
  const [stageStatus, setStageStatus] = useState<{
    passive_recon?: StageStatus;
    active_recon?: StageStatus;
  }>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedTools, setSelectedTools] = useState<{
    'passive-recon': string[];
    'active-recon': string[];
    'vulnerability-scanning': string[];
    'vulnerability-testing': string[];
    'kill-chain': string[];
    'report-generation': string[];
  }>({
    'passive-recon': [],
    'active-recon': [],
    'vulnerability-scanning': [],
    'vulnerability-testing': [],
    'kill-chain': [],
    'report-generation': []
  });
  const [selectedStages, setSelectedStages] = useState<{
    'passive-recon': boolean;
    'active-recon': boolean;
    'vulnerability-scanning': boolean;
    'vulnerability-testing': boolean;
    'kill-chain': boolean;
    'report-generation': boolean;
  }>({
    'passive-recon': true,
    'active-recon': true,
    'vulnerability-scanning': true,
    'vulnerability-testing': true,
    'kill-chain': true,
    'report-generation': true
  });
  const [primaryTarget, setPrimaryTarget] = useState<any>(null);

  const stages = [
    {
      id: 'passive-recon',
      title: 'Passive Recon',
      tools: [
        'Sublist3r', 'Amass', 'Subfinder', 'Assetfinder', 'Gau', 'Waybackurls',
        'Httpx', 'Nuclei', 'Naabu', 'Katana', 'Feroxbuster', 'Gobuster',
        'LinkFinder', 'GetJS', 'EyeWitness', 'EyeBaller', 'WebAnalyze',
        'WhatWeb', 'FingerprintX', 'Arjun', 'MassDNS', 'PureDNS', 'FFuf',
        'WAFW00F', 'CloudFail', 'CloudEnum', 'S3Enum'
      ]
    },
    {
      id: 'active-recon',
      title: 'Active Recon',
      tools: [
        'Nmap', 'Httpx', 'Feroxbuster', 'Katana', 'Eyewitness', 'Webanalyze',
        'Enhanced Subdomain Enum', 'WAF/CDN Detection', 'Cloud Infrastructure',
        'Input Vectors Discovery', 'Dynamic Analysis', 'Misconfiguration Detection',
        'Port Scanning', 'Service Detection', 'Technology Fingerprinting',
        'Directory Enumeration', 'Parameter Discovery', 'API Endpoint Discovery'
      ]
    },
    {
      id: 'vulnerability-scanning',
      title: 'Vulnerability Scanning',
      tools: ['Nuclei', 'Nmap Scripts', 'Custom Scanners', 'Port Analysis', 'Service Detection', 'Version Detection']
    },
    {
      id: 'vulnerability-testing',
      title: 'Vulnerability Testing',
      tools: ['SQLMap', 'FFuf', 'Custom Payloads', 'Manual Testing', 'Proof of Concept', 'Exploit Validation']
    },
    {
      id: 'kill-chain',
      title: 'Kill Chain',
      tools: ['Attack Path Analysis', 'Chain Validation', 'Screenshot Capture', 'POC Generation', 'Impact Assessment', 'Risk Analysis']
    },
    {
      id: 'report-generation',
      title: 'Report Generation',
      tools: ['Template Engine', 'Data Aggregation', 'Chart Generation', 'PDF Export', 'Executive Summary', 'Technical Details']
    }
  ];

  // Fetch primary target info
  const fetchPrimaryTarget = async () => {
    try {
      const response = await getTargets({ is_primary: true, status: TargetStatus.ACTIVE });
      if (response.success && response.data?.items?.length > 0) {
        const primary = response.data.items[0];
        setPrimaryTarget(primary);
        
        // Set the target as active if it's not already
        if (primary.status !== TargetStatus.ACTIVE) {
          await updateTarget(primary.id, { status: TargetStatus.ACTIVE });
        }
      }
    } catch (error) {
      console.error('Failed to fetch primary target:', error);
    }
  };

  // Fetch stage data and status
  const fetchStageData = async () => {
    if (!primaryTarget?.id) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const [summaryData, passiveStatus, activeStatus] = await Promise.allSettled([
        getStageSummary(primaryTarget.id),
        getPassiveReconStatus(primaryTarget.id),
        getActiveReconStatus(primaryTarget.id)
      ]);

      if (summaryData.status === 'fulfilled') {
        setStageData(summaryData.value);
      }

      if (passiveStatus.status === 'fulfilled' && passiveStatus.value) {
        setStageStatus(prev => ({ ...prev, passive_recon: passiveStatus.value as StageStatus }));
      }

      if (activeStatus.status === 'fulfilled' && activeStatus.value) {
        setStageStatus(prev => ({ ...prev, active_recon: activeStatus.value as StageStatus }));
      }
    } catch (err) {
      console.error('Failed to fetch stage data:', err);
      setError('Failed to fetch stage data');
    } finally {
      setLoading(false);
    }
  };

  const handleStartStage = async (stageName: string, toolsToRun: string[], options?: Record<string, any>) => {
    if (!primaryTarget?.id) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const request = {
        target_id: primaryTarget.id,
        stage_name: stageName,
        tools: toolsToRun.length > 0 ? toolsToRun : undefined,
        options: options || {}
      };

      let result;
      if (stageName === 'passive-recon') {
        result = await startPassiveRecon(request);
      } else if (stageName === 'active-recon') {
        result = await startActiveRecon(request);
      } else {
        throw new Error(`Stage ${stageName} not implemented yet`);
      }

      console.log(`Started ${stageName} with tools:`, toolsToRun.length > 0 ? toolsToRun : 'all tools');
      
      // Refresh data after starting
      setTimeout(fetchStageData, 1000);
    } catch (err) {
      console.error(`Failed to start ${stageName}:`, err);
      setError(`Failed to start ${stageName}`);
    } finally {
      setLoading(false);
    }
  };

  // Handle tool selection changes
  const handleToolSelectionChange = (stageName: string, tool: string, checked: boolean) => {
    setSelectedTools(prev => {
      const currentStageTools = prev[stageName as keyof typeof prev] || [];
      
      if (tool === 'All') {
        if (checked) {
          // If "All" is checked, clear the selection (empty array means all tools)
          return {
            ...prev,
            [stageName]: []
          };
        } else {
          // If "All" is unchecked, keep current selection (allows individual tool selection)
          return {
            ...prev,
            [stageName]: currentStageTools
          };
        }
      } else {
        // Handle individual tool selection
        let newTools: string[];
        if (checked) {
          newTools = [...currentStageTools, tool];
        } else {
          newTools = currentStageTools.filter((t: string) => t !== tool);
        }
        
        return {
          ...prev,
          [stageName]: newTools
        };
      }
    });
  };

  // Handle stage selection changes
  const handleStageSelectionChange = (stageName: string, checked: boolean) => {
    setSelectedStages(prev => ({
      ...prev,
      [stageName]: checked
    }));
  };

  // Handle workflow start
  const handleStartWorkflow = async () => {
    if (!primaryTarget?.id) {
      setError('No primary target found');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Get selected stages
      const selectedStageNames = Object.entries(selectedStages)
        .filter(([_, isSelected]) => isSelected)
        .map(([stageName, _]) => stageName);

      if (selectedStageNames.length === 0) {
        setError('Please select at least one stage to run');
        return;
      }

      // Start each selected stage
      for (const stageName of selectedStageNames) {
        const stageTools = selectedTools[stageName as keyof typeof selectedTools] || [];
        await handleStartStage(stageName, stageTools);
      }

      console.log('Started workflow with stages:', selectedStageNames);
    } catch (err) {
      console.error('Failed to start workflow:', err);
      setError('Failed to start workflow');
    } finally {
      setLoading(false);
    }
  };

  // Set up polling for status updates
  useEffect(() => {
    fetchPrimaryTarget();
  }, []);

  useEffect(() => {
    if (primaryTarget?.id) {
      fetchStageData();
      
      // Poll for status updates every 5 seconds
      const interval = setInterval(fetchStageData, 5000);
      
      return () => clearInterval(interval);
    }
  }, [primaryTarget?.id]);

  const getStageData = (stageId: string) => {
    if (!stageData) return { results: [], status: undefined };
    
    switch (stageId) {
      case 'passive-recon':
        return {
          results: stageData.passive_recon.results,
          status: stageStatus.passive_recon
        };
      case 'active-recon':
        return {
          results: stageData.active_recon.results,
          status: stageStatus.active_recon
        };
      default:
        return { results: [], status: undefined };
    }
  };

  const isStageRunning = (stageId: string) => {
    const status = getStageData(stageId).status;
    return status?.status === 'running';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <OverlayManager activeOverlay={activeOverlay} setActiveOverlay={setActiveOverlay}>
        <Header 
          onNavigationClick={() => setActiveOverlay('navigation')}
          onSettingsClick={() => setActiveOverlay('settings')}
        />
        
        <main className="container mx-auto px-6 py-8 space-y-8">
          {/* Target Profile Summary */}
          <TargetProfileCard target={primaryTarget || target} />
          
          {/* Error message */}
          {error && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-4 text-red-300">
              {error}
            </div>
          )}
          
          {/* Stage Selection Grid - 2 rows x 3 columns */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-7xl mx-auto">
            {stages.map((stage) => {
              const { results, status } = getStageData(stage.id);
              const isRunning = isStageRunning(stage.id);
              const stageSelectedTools = selectedTools[stage.id as keyof typeof selectedTools] || [];
              const isStageSelected = selectedStages[stage.id as keyof typeof selectedStages] || false;
              
              return (
                <StageCard
                  key={stage.id}
                  id={stage.id}
                  title={stage.title}
                  tools={stage.tools}
                  targetId={primaryTarget?.id}
                  status={status}
                  results={results}
                  selectedTools={stageSelectedTools}
                  isStageSelected={isStageSelected}
                  onToolChange={(tool, checked) => handleToolSelectionChange(stage.id, tool, checked)}
                  onStageSelectionChange={(checked) => handleStageSelectionChange(stage.id, checked)}
                  onStartStage={handleStartStage}
                  isRunning={isRunning}
                />
              );
            })}
          </div>
          
          {/* Recursive Recon Results */}
          {stageData?.recursive_recon.has_data && (
            <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-white mb-4">Recursive Reconnaissance Results</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div className="text-center">
                  <div className="text-blue-400 font-semibold text-xl">
                    {stageData.recursive_recon.results?.total_subdomains || 0}
                  </div>
                  <div className="text-gray-500">Subdomains</div>
                </div>
                <div className="text-center">
                  <div className="text-green-400 font-semibold text-xl">
                    {stageData.recursive_recon.results?.subtargets_created || 0}
                  </div>
                  <div className="text-gray-500">Subtargets</div>
                </div>
                <div className="text-center">
                  <div className="text-yellow-400 font-semibold text-xl">
                    {stageData.recursive_recon.results?.passive_recon_success_rate?.toFixed(1) || 0}%
                  </div>
                  <div className="text-gray-500">Passive Success</div>
                </div>
                <div className="text-center">
                  <div className="text-purple-400 font-semibold text-xl">
                    {stageData.recursive_recon.results?.active_recon_success_rate?.toFixed(1) || 0}%
                  </div>
                  <div className="text-gray-500">Active Success</div>
                </div>
              </div>
            </div>
          )}
          
          {/* Start Button - Moved closer to stage cards */}
          <div className="flex justify-center pt-4">
            <StartButton onClick={handleStartWorkflow} disabled={loading || !primaryTarget?.id} />
          </div>
        </main>
      </OverlayManager>
    </div>
  );
} 