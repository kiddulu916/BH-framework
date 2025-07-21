'use client';

import React, { useState } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import { Plus, X } from 'lucide-react';

export default function ScopeConfigStep() {
  const { formData, updateFormData } = useTargetFormStore();

  const [inScope, setInScope] = useState<string[]>(formData.in_scope || []);
  const [outOfScope, setOutOfScope] = useState<string[]>(formData.out_of_scope || []);

  const [newInScopeUrl, setNewInScopeUrl] = useState('');
  const [newOutOfScopeUrl, setNewOutOfScopeUrl] = useState('');

  const handleAddInScope = () => {
    if (newInScopeUrl.trim()) {
      setInScope([...inScope, newInScopeUrl]);
      setNewInScopeUrl('');
    }
  };

  const handleRemoveInScope = (index: number) => {
    setInScope(inScope.filter((_, i) => i !== index));
  };

  const handleAddOutOfScope = () => {
    if (newOutOfScopeUrl.trim()) {
      setOutOfScope([...outOfScope, newOutOfScopeUrl]);
      setNewOutOfScopeUrl('');
    }
  };

  const handleRemoveOutOfScope = (index: number) => {
    setOutOfScope(outOfScope.filter((_, i) => i !== index));
  };

  const handleSave = () => {
    updateFormData({ in_scope: inScope, out_of_scope: outOfScope });
    alert('Step 3 data saved!');
  };

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Scope Configuration</h3>
      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">In Scope URLs</label>
        <div className="flex items-center gap-2">
          <Input
            label=""
            placeholder="*.example.com"
            value={newInScopeUrl}
            onChange={(e) => setNewInScopeUrl(e.target.value)}
          />
          <button onClick={handleAddInScope} className="text-gray-400 hover:text-green-500">
            <Plus size={20} />
          </button>
        </div>
        <div className="mt-2 space-y-2">
          {inScope.map((url, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{url}</span>
              <button onClick={() => handleRemoveInScope(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>
      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Out of Scope URLs</label>
        <div className="flex items-center gap-2">
          <Input
            label=""
            placeholder="*.sistercompany.com"
            value={newOutOfScopeUrl}
            onChange={(e) => setNewOutOfScopeUrl(e.target.value)}
          />
          <button onClick={handleAddOutOfScope} className="text-gray-400 hover:text-green-500">
            <Plus size={20} />
          </button>
        </div>
        <div className="mt-2 space-y-2">
          {outOfScope.map((url, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{url}</span>
              <button onClick={() => handleRemoveOutOfScope(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>
      <div className="text-center">
        <button
          onClick={handleSave}
          className="px-4 py-2 bg-blue-600 text-white rounded-md font-medium shadow hover:bg-blue-700 transition"
        >
          Save Step Data
        </button>
      </div>
    </div>
  );
}; 