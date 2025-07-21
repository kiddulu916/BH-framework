'use client';

import React, { useState } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import { Plus, X } from 'lucide-react';

export default function AdditionalRulesStep() {
  const { formData, updateFormData } = useTargetFormStore();
  const [rulesToFollow, setRulesToFollow] = useState<string[]>(formData.rules_to_follow || []);
  const [rulesToAvoid, setRulesToAvoid] = useState<string[]>(formData.rules_to_avoid || []);
  const [newRuleToFollow, setNewRuleToFollow] = useState('');
  const [newRuleToAvoid, setNewRuleToAvoid] = useState('');

  const handleAddRuleToFollow = () => {
    if (newRuleToFollow.trim()) {
      setRulesToFollow([...rulesToFollow, newRuleToFollow]);
      setNewRuleToFollow('');
    }
  };

  const handleRemoveRuleToFollow = (index: number) => {
    setRulesToFollow(rulesToFollow.filter((_, i) => i !== index));
  };

  const handleAddRuleToAvoid = () => {
    if (newRuleToAvoid.trim()) {
      setRulesToAvoid([...rulesToAvoid, newRuleToAvoid]);
      setNewRuleToAvoid('');
    }
  };

  const handleRemoveRuleToAvoid = (index: number) => {
    setRulesToAvoid(rulesToAvoid.filter((_, i) => i !== index));
  };

  const handleSave = () => {
    updateFormData({ rules_to_follow: rulesToFollow, rules_to_avoid: rulesToAvoid });
    alert('Step 4 data saved!');
  };

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Additional Rules</h3>
      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Rules to Follow</label>
        <div className="flex items-center gap-2">
          <Input
            label=""
            placeholder="e.g. Do not test during business hours"
            value={newRuleToFollow}
            onChange={(e) => setNewRuleToFollow(e.target.value)}
          />
          <button onClick={handleAddRuleToFollow} className="text-gray-400 hover:text-green-500">
            <Plus size={20} />
          </button>
        </div>
        <div className="mt-2 space-y-2">
          {rulesToFollow.map((rule, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{rule}</span>
              <button onClick={() => handleRemoveRuleToFollow(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>
      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Rules to Avoid</label>
        <div className="flex items-center gap-2">
          <Input
            label=""
            placeholder="e.g. Do not perform DDoS attacks"
            value={newRuleToAvoid}
            onChange={(e) => setNewRuleToAvoid(e.target.value)}
          />
          <button onClick={handleAddRuleToAvoid} className="text-gray-400 hover:text-green-500">
            <Plus size={20} />
          </button>
        </div>
        <div className="mt-2 space-y-2">
          {rulesToAvoid.map((rule, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{rule}</span>
              <button onClick={() => handleRemoveRuleToAvoid(index)} className="text-gray-400 hover:text-red-500">
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