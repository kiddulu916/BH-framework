'use client';

import React, { useState } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';

export default function RateLimitStep() {
  const { formData, updateFormData } = useTargetFormStore();
  const [requests, setRequests] = useState(formData.rate_limit_requests || 0);
  const [seconds, setSeconds] = useState(formData.rate_limit_seconds || 0);

  const handleSave = () => {
    updateFormData({
      rate_limit_requests: Number(requests),
      rate_limit_seconds: Number(seconds),
    });
    alert('Step 5 data saved!');
  };

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Rate Limiting</h3>
      <p className="text-center text-gray-400 mb-8">
        Specify the maximum number of requests per time interval.
      </p>
      <div className="flex items-center gap-4 mb-6">
        <Input
          label="Max Requests"
          type="number"
          placeholder="e.g. 100"
          value={requests}
          onChange={(e) => setRequests(Number(e.target.value))}
        />
        <span className="text-gray-200 mt-8">per</span>
        <Input
          label="Time (seconds)"
          type="number"
          placeholder="e.g. 60"
          value={seconds}
          onChange={(e) => setSeconds(Number(e.target.value))}
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