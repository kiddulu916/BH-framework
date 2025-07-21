'use client';

import React from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';

export default function ReviewStep() {
  const { formData } = useTargetFormStore();

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Review and Confirm</h3>
      <div className="space-y-4 text-gray-300">
        <div><strong>Target Company:</strong> {formData.target}</div>
        <div><strong>Domain/IP:</strong> {formData.domain}</div>
        <div><strong>Primary Target:</strong> {formData.is_primary ? 'Yes' : 'No'}</div>
        <div><strong>Platform:</strong> {formData.platform}</div>
        <div><strong>Login Email:</strong> {formData.platform_email}</div>
        <div><strong>Researcher Email:</strong> {formData.researcher_email}</div>
        <div>
          <strong>In Scope:</strong>
          <ul className="list-disc list-inside ml-4">
            {(formData.in_scope || []).map((item, index) => <li key={index}>{item}</li>)}
          </ul>
        </div>
        <div>
          <strong>Out of Scope:</strong>
          <ul className="list-disc list-inside ml-4">
            {(formData.out_of_scope || []).map((item, index) => <li key={index}>{item}</li>)}
          </ul>
        </div>
        <div>
          <strong>Rules to Follow:</strong>
          <ul className="list-disc list-inside ml-4">
            {(formData.rules_to_follow || []).map((item, index) => <li key={index}>{item}</li>)}
          </ul>
        </div>
        <div>
          <strong>Rules to Avoid:</strong>
          <ul className="list-disc list-inside ml-4">
            {(formData.rules_to_avoid || []).map((item, index) => <li key={index}>{item}</li>)}
          </ul>
        </div>
        <div>
          <strong>Rate Limit:</strong> {formData.rate_limit_requests} requests per {formData.rate_limit_seconds} seconds
        </div>
      </div>
    </div>
  );
}; 