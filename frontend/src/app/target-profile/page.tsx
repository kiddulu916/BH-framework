'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Plus, Users, ArrowLeft } from 'lucide-react';
import { getTargets, updateTarget, deleteTarget } from '@/lib/api/targets';
import { TargetStatus } from '@/types/target';

interface Target {
  id: string;
  target: string;
  domain: string;
  status: TargetStatus;
  is_primary: boolean;
  platform: string;
  created_at: string;
  updated_at: string;
  description?: string;
  scope?: string;
  bounty_range?: string;
}

export default function TargetProfilePage() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[]>([]);
  const [primaryTarget, setPrimaryTarget] = useState<Target | null>(null);
  const [activeTarget, setActiveTarget] = useState<Target | null>(null);
  const [loading, setLoading] = useState(true);
  const [showTargetSelector, setShowTargetSelector] = useState(false);

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    try {
      setLoading(true);
      const response = await getTargets();
      if (response.success && response.data?.items) {
        const targetList = response.data.items;
        setTargets(targetList);
        
        // Find primary target
        const primary = targetList.find((t: Target) => t.is_primary);
        setPrimaryTarget(primary || null);
        
        // Find active target (could be primary or another target)
        const active = targetList.find((t: Target) => t.status === TargetStatus.ACTIVE);
        setActiveTarget(active || null);
      }
    } catch (error) {
      console.error('Failed to fetch targets:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNewTarget = () => {
    router.push('/target-create');
  };

  const handleChooseTarget = () => {
    setShowTargetSelector(true);
  };

  const handleBackToDashboard = () => {
    router.push('/dashboard');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-400">Loading target information...</p>
        </div>
      </div>
    );
  }

  // If no targets exist, redirect to target creation
  if (targets.length === 0) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-center max-w-md mx-auto p-8">
          <div className="bg-gray-800 rounded-2xl p-8 border border-gray-700">
            <Users className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h1 className="text-2xl font-bold text-white mb-4">No Targets Found</h1>
            <p className="text-gray-400 mb-6">
              You haven't created any targets yet. Create your first target to get started with bug hunting.
            </p>
            <button
              onClick={handleCreateNewTarget}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors duration-200 flex items-center justify-center space-x-2"
            >
              <Plus className="w-5 h-5" />
              <span>Create First Target</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="bg-gray-800/95 backdrop-blur-sm border-b border-gray-700/50 px-6 py-4">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <div className="flex items-center space-x-4">
            <button
              onClick={handleBackToDashboard}
              className="p-2 rounded-lg hover:bg-gray-700/50 transition-colors duration-200"
            >
              <ArrowLeft className="w-5 h-5 text-gray-300" />
            </button>
            <h1 className="text-2xl font-bold text-white">Target Profile</h1>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={handleChooseTarget}
              className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors duration-200 flex items-center space-x-2"
            >
              <Users className="w-4 h-4" />
              <span>Choose Target</span>
            </button>
            <button
              onClick={handleCreateNewTarget}
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors duration-200 flex items-center space-x-2"
            >
              <Plus className="w-4 h-4" />
              <span>Create New Target</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        {activeTarget ? (
          <div className="space-y-6">
            {/* Target Overview Card */}
            <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-white">{activeTarget.target}</h2>
                <div className="flex items-center space-x-2">
                  {activeTarget.is_primary && (
                    <span className="bg-blue-600 text-white text-xs px-2 py-1 rounded-full">
                      Primary
                    </span>
                  )}
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    activeTarget.status === TargetStatus.ACTIVE 
                      ? 'bg-green-600 text-white' 
                      : 'bg-gray-600 text-gray-300'
                  }`}>
                    {activeTarget.status}
                  </span>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-400">Domain</label>
                  <p className="text-white">{activeTarget.domain}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-400">Platform</label>
                  <p className="text-white">{activeTarget.platform}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-400">Created</label>
                  <p className="text-white">{new Date(activeTarget.created_at).toLocaleDateString()}</p>
                </div>
                {activeTarget.description && (
                  <div className="md:col-span-2">
                    <label className="text-sm font-medium text-gray-400">Description</label>
                    <p className="text-white">{activeTarget.description}</p>
                  </div>
                )}
                {activeTarget.scope && (
                  <div className="md:col-span-2">
                    <label className="text-sm font-medium text-gray-400">Scope</label>
                    <p className="text-white">{activeTarget.scope}</p>
                  </div>
                )}
                {activeTarget.bounty_range && (
                  <div>
                    <label className="text-sm font-medium text-gray-400">Bounty Range</label>
                    <p className="text-white">{activeTarget.bounty_range}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Target Statistics */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h3 className="text-lg font-semibold text-white mb-4">Reconnaissance</h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Subdomains Found</span>
                    <span className="text-white font-semibold">0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Endpoints Discovered</span>
                    <span className="text-white font-semibold">0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Technologies</span>
                    <span className="text-white font-semibold">0</span>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h3 className="text-lg font-semibold text-white mb-4">Vulnerabilities</h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Critical</span>
                    <span className="text-red-400 font-semibold">0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">High</span>
                    <span className="text-orange-400 font-semibold">0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Medium</span>
                    <span className="text-yellow-400 font-semibold">0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Low</span>
                    <span className="text-blue-400 font-semibold">0</span>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h3 className="text-lg font-semibold text-white mb-4">Progress</h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Stages Completed</span>
                    <span className="text-white font-semibold">0/6</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Tools Run</span>
                    <span className="text-white font-semibold">0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Success Rate</span>
                    <span className="text-green-400 font-semibold">0%</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-12">
            <div className="bg-gray-800 rounded-2xl p-8 border border-gray-700 max-w-md mx-auto">
              <Users className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h2 className="text-xl font-semibold text-white mb-4">No Active Target</h2>
              <p className="text-gray-400 mb-6">
                You have targets but none are currently active. Choose a target to view its profile.
              </p>
              <button
                onClick={handleChooseTarget}
                className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors duration-200"
              >
                Choose Target
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Target Selector Overlay */}
      {showTargetSelector && (
        <TargetSelectorOverlay
          targets={targets}
          onClose={() => setShowTargetSelector(false)}
          onTargetSelect={async (targetId, makePrimary) => {
            try {
              const selectedTarget = targets.find(t => t.id === targetId);
              if (!selectedTarget) return;

              // If making this target primary, first unset all other primary targets
              if (makePrimary) {
                for (const target of targets) {
                  if (target.is_primary && target.id !== targetId) {
                    await updateTarget(target.id, { is_primary: false });
                  }
                }
                await updateTarget(targetId, { is_primary: true });
              }

              // Set this target as active and deactivate all others
              for (const target of targets) {
                if (target.status === TargetStatus.ACTIVE && target.id !== targetId) {
                  await updateTarget(target.id, { status: TargetStatus.INACTIVE });
                }
              }
              await updateTarget(targetId, { status: TargetStatus.ACTIVE });

              setShowTargetSelector(false);
              await fetchTargets(); // Refresh targets
            } catch (error) {
              console.error('Failed to select target:', error);
            }
          }}
        />
      )}
    </div>
  );
}

interface TargetSelectorOverlayProps {
  targets: Target[];
  onClose: () => void;
  onTargetSelect: (targetId: string, makePrimary: boolean) => void;
}

function TargetSelectorOverlay({ targets, onClose, onTargetSelect }: TargetSelectorOverlayProps) {
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [makePrimary, setMakePrimary] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deletingTarget, setDeletingTarget] = useState<string | null>(null);

  const handleSelectTarget = () => {
    if (selectedTarget) {
      onTargetSelect(selectedTarget, makePrimary);
    }
  };

  const handleDeleteTarget = async (targetId: string) => {
    try {
      setDeletingTarget(targetId);
      await deleteTarget(targetId);
      setShowDeleteConfirm(false);
      setDeletingTarget(null);
      // Refresh the target list
      window.location.reload();
    } catch (error) {
      console.error('Failed to delete target:', error);
      setDeletingTarget(null);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700 max-w-md w-full">
        <h3 className="text-xl font-semibold text-white mb-4">Choose Target</h3>
        
        <div className="space-y-4 mb-6">
          {targets.map((target) => (
            <div key={target.id} className="flex items-center space-x-3">
              <label className="flex items-center space-x-3 cursor-pointer flex-1">
                <input
                  type="radio"
                  name="target"
                  value={target.id}
                  checked={selectedTarget === target.id}
                  onChange={(e) => setSelectedTarget(e.target.value)}
                  className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600"
                />
                <div className="flex-1">
                  <div className="text-white font-medium">{target.target}</div>
                  <div className="text-gray-400 text-sm">{target.domain}</div>
                  <div className="flex items-center space-x-2 mt-1">
                    {target.is_primary && (
                      <span className="bg-blue-600 text-white text-xs px-2 py-1 rounded-full">
                        Primary
                      </span>
                    )}
                    <span className={`text-xs px-2 py-1 rounded-full ${
                      target.status === TargetStatus.ACTIVE 
                        ? 'bg-green-600 text-white' 
                        : 'bg-gray-600 text-gray-300'
                    }`}>
                      {target.status}
                    </span>
                  </div>
                </div>
              </label>
              
              {/* Delete button */}
              <button
                onClick={() => {
                  setSelectedTarget(target.id);
                  setShowDeleteConfirm(true);
                }}
                className="p-2 text-red-400 hover:text-red-300 hover:bg-red-900/20 rounded-lg transition-colors duration-200"
                title="Delete target"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          ))}
        </div>

        {selectedTarget && (
          <div className="mb-6">
            <label className="flex items-center space-x-3 cursor-pointer">
              <input
                type="checkbox"
                checked={makePrimary}
                onChange={(e) => setMakePrimary(e.target.checked)}
                className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded"
              />
              <span className="text-gray-300 text-sm">
                Make this target the primary target
              </span>
            </label>
          </div>
        )}

        <div className="flex space-x-3">
          <button
            onClick={onClose}
            className="flex-1 bg-gray-700 hover:bg-gray-600 text-white py-2 px-4 rounded-lg transition-colors duration-200"
          >
            Cancel
          </button>
          <button
            onClick={handleSelectTarget}
            disabled={!selectedTarget}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white py-2 px-4 rounded-lg transition-colors duration-200"
          >
            Select Target
          </button>
        </div>

        {/* Delete confirmation modal */}
        {showDeleteConfirm && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-60 flex items-center justify-center p-4">
            <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700 max-w-md w-full">
              <h4 className="text-lg font-semibold text-white mb-4">Delete Target</h4>
              <p className="text-gray-300 mb-6">
                Are you sure you want to delete this target? This action cannot be undone.
              </p>
              <div className="flex space-x-3">
                <button
                  onClick={() => setShowDeleteConfirm(false)}
                  className="flex-1 bg-gray-700 hover:bg-gray-600 text-white py-2 px-4 rounded-lg transition-colors duration-200"
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleDeleteTarget(selectedTarget)}
                  disabled={deletingTarget === selectedTarget}
                  className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white py-2 px-4 rounded-lg transition-colors duration-200"
                >
                  {deletingTarget === selectedTarget ? 'Deleting...' : 'Delete'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
} 