'use client';

import React, { useState } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Select from '@/components/atoms/Select';
import Input from '@/components/atoms/Input';
import { BugBountyPlatform } from '@/types/target';

export default function ProgramDetailsStep() {
  const { formData, updateFormData } = useTargetFormStore();
  const [platform, setPlatform] = useState(formData.platform || BugBountyPlatform.HACKERONE);
  const [platformEmail, setPlatformEmail] = useState(formData.platform_email || '');
  const [researcherEmail, setResearcherEmail] = useState(formData.researcher_email || '');

  const platformOptions = [
    { value: BugBountyPlatform.HACKERONE, label: 'HackerOne' },
    { value: BugBountyPlatform.BUGCROWD, label: 'Bugcrowd' },
    { value: BugBountyPlatform.CUSTOM, label: 'Custom/Private Program' },
  ];

  const handleSave = () => {
    updateFormData({ platform, platform_email: platformEmail, researcher_email: researcherEmail });
    alert('Step 2 data saved!');
  };

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Bug Bounty Program Details</h3>
      <div className="mb-6">
        <Select
          label="Platform:"
          options={platformOptions}
          value={platform}
          onChange={(e) => setPlatform(e.target.value as BugBountyPlatform)}
        />
      </div>
      <div className="mb-6">
        <Input
          label="Login Email:"
          type="email"
          placeholder="login@example.com"
          value={platformEmail}
          onChange={(e) => setPlatformEmail(e.target.value)}
          title="Email you use to login for report generation"
        />
      </div>
      <div className="mb-6">
        <Input
          label="Researcher Email:"
          type="email"
          placeholder="researcher@example.com"
          value={researcherEmail}
          onChange={(e) => setResearcherEmail(e.target.value)}
          title="Email provided by the platform for research purposes"
        />
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