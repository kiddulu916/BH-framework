'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { CheckboxGroup } from '@/components/molecules/CheckboxGroup';
import { StageStatus, StageResult } from '@/lib/api/stages';

interface StageCardProps {
  id: string;
  title: string;
  tools: string[];
  targetId?: string;
  status?: StageStatus;
  results?: StageResult[];
  selectedTools?: string[];
  onToolChange?: (tool: string, checked: boolean) => void;
  onStartStage?: (stageName: string, selectedTools: string[], options?: Record<string, any>) => void;
  isRunning?: boolean;
}

export function StageCard({ 
  id, 
  title, 
  tools, 
  targetId, 
  status, 
  results = [], 
  selectedTools: propSelectedTools = [],
  onToolChange,
  onStartStage,
  isRunning = false 
}: StageCardProps) {
  const [showDetails, setShowDetails] = useState(false);

  const handleToolChange = (tool: string, checked: boolean) => {
    if (onToolChange) {
      onToolChange(tool, checked);
    }
  };

  const handleStartStage = () => {
    if (onStartStage && targetId) {
      // If no tools are selected, run all tools (empty array means all)
      const toolsToRun = propSelectedTools.length > 0 ? propSelectedTools : [];
      onStartStage(id, toolsToRun);
    }
  };

  const getStatusColor = () => {
    if (isRunning) return 'bg-yellow-500';
    if (status?.status === 'completed') return 'bg-green-500';
    if (status?.status === 'failed') return 'bg-red-500';
    if (status?.status === 'running') return 'bg-blue-500';
    return 'bg-gray-500';
  };

  const getStatusText = () => {
    if (isRunning) return 'Running';
    if (status?.status === 'completed') return 'Completed';
    if (status?.status === 'failed') return 'Failed';
    if (status?.status === 'running') return 'Running';
    if (status?.status === 'pending') return 'Pending';
    return 'Not Started';
  };

  const getProgressPercentage = () => {
    if (!status) return 0;
    if (status.total_tools === 0) return 0;
    return Math.round((status.completed_tools / status.total_tools) * 100);
  };

  const getResultsSummary = () => {
    if (!results || results.length === 0) return null;
    
    const successfulTools = results.filter(r => r.data?.success !== false).length;
    const totalTools = results.length;
    
    return {
      total: totalTools,
      successful: successfulTools,
      failed: totalTools - successfulTools,
      successRate: Math.round((successfulTools / totalTools) * 100)
    };
  };

  const resultsSummary = getResultsSummary();

  return (
    <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700 hover:border-gray-600 transition-all duration-300 hover:shadow-xl hover:shadow-gray-900/20 group">
      {/* Header with status indicator */}
      <div className="flex items-center justify-between mb-4">
        <Link
          href={`/stages/${id}`}
          className="flex-1"
        >
          <h3 className="text-lg font-semibold text-white hover:text-blue-400 transition-colors duration-200 cursor-pointer group-hover:text-blue-400">
            {title}
          </h3>
        </Link>
        
        {/* Status indicator */}
        <div className="flex items-center space-x-2">
          <div className={`w-3 h-3 rounded-full ${getStatusColor()}`}></div>
          <span className="text-sm text-gray-300">{getStatusText()}</span>
        </div>
      </div>

      {/* Progress bar */}
      {status && (
        <div className="mb-4">
          <div className="flex justify-between text-sm text-gray-400 mb-1">
            <span>Progress</span>
            <span>{getProgressPercentage()}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div 
              className={`h-2 rounded-full transition-all duration-300 ${getStatusColor()}`}
              style={{ width: `${getProgressPercentage()}%` }}
            ></div>
          </div>
          {status.total_tools > 0 && (
            <div className="text-xs text-gray-500 mt-1">
              {status.completed_tools}/{status.total_tools} tools completed
            </div>
          )}
        </div>
      )}

      {/* Results summary */}
      {resultsSummary && (
        <div className="mb-4 p-3 bg-gray-750 rounded-lg">
          <div className="text-sm font-medium text-gray-300 mb-2">Results Summary</div>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="text-center">
              <div className="text-green-400 font-semibold">{resultsSummary.successful}</div>
              <div className="text-gray-500">Success</div>
            </div>
            <div className="text-center">
              <div className="text-red-400 font-semibold">{resultsSummary.failed}</div>
              <div className="text-gray-500">Failed</div>
            </div>
            <div className="text-center">
              <div className="text-blue-400 font-semibold">{resultsSummary.successRate}%</div>
              <div className="text-gray-500">Rate</div>
            </div>
          </div>
        </div>
      )}

      {/* Tools section */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-300">Tools</span>
          <button
            onClick={() => setShowDetails(!showDetails)}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            {showDetails ? 'Hide' : 'Show'} Details
          </button>
        </div>
        
        {showDetails ? (
          <div className="pointer-events-auto">
            <CheckboxGroup
              tools={tools}
              selectedTools={propSelectedTools}
              onToolChange={handleToolChange}
            />
          </div>
        ) : (
          <div className="text-xs text-gray-400">
            {propSelectedTools.length > 0 
              ? `${propSelectedTools.length} of ${tools.length} tools selected`
              : `${tools.length} tools available (all will run)`
            }
          </div>
        )}
      </div>

      {/* Action buttons */}
      <div className="flex space-x-2">
        {onStartStage && targetId && (
          <button
            onClick={handleStartStage}
            disabled={isRunning || status?.status === 'running'}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-sm font-medium py-2 px-4 rounded-lg transition-colors duration-200"
          >
            {isRunning || status?.status === 'running' ? 'Running...' : 'Start Stage'}
          </button>
        )}
        
        <Link
          href={`/stages/${id}${targetId ? `?target=${targetId}` : ''}`}
          className="bg-gray-700 hover:bg-gray-600 text-white text-sm font-medium py-2 px-4 rounded-lg transition-colors duration-200"
        >
          View Details
        </Link>
      </div>

      {/* Selected tools indicator */}
      {propSelectedTools.length > 0 && (
        <div className="mt-3 p-2 bg-blue-900/20 border border-blue-700 rounded text-xs">
          <div className="text-blue-300 font-medium mb-1">Selected Tools:</div>
          <div className="text-blue-400">
            {propSelectedTools.slice(0, 3).join(', ')}
            {propSelectedTools.length > 3 && ` +${propSelectedTools.length - 3} more`}
          </div>
        </div>
      )}

      {/* Error message */}
      {status?.error && (
        <div className="mt-3 p-2 bg-red-900/20 border border-red-700 rounded text-xs text-red-300">
          Error: {status.error}
        </div>
      )}
    </div>
  );
} 