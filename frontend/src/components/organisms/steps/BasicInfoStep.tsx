'use client';

import React, { useState } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';

export default function BasicInfoStep() {
  const { formData, updateFormData } = useTargetFormStore();
  const [target, setTarget] = useState(formData.target || '');
  const [domain, setDomain] = useState(formData.domain || '');
  const [isPrimary, setIsPrimary] = useState(formData.is_primary || false);

  const handleSave = () => {
    updateFormData({ target, domain, is_primary: isPrimary });
    alert('Step 1 data saved!');
  };

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Build Target Profile</h3>
      <div className="mb-6">
        <Input
          label="Target Company:"
          placeholder="e.g. Example LLC."
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
      </div>
      <div className="mb-6">
        <Input
          label="Domain/IP Adress"
          placeholder="e.g. example.com, 196.258.0.1"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
      </div>
      <div className="flex items-center mb-6">
        <input
          type="checkbox"
          id="is_primary"
          checked={isPrimary}
          onChange={(e) => setIsPrimary(e.target.checked)}
          className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded bg-zinc-800"
        />
        <label htmlFor="is_primary" className="ml-2 text-gray-200 text-sm select-none">
          Set as Primary Target
        </label>
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