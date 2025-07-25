'use client';

import React, { useImperativeHandle } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import { StepRef } from './BasicInfoStep';

export default function ReviewStep({ stepRef }: { stepRef: React.RefObject<StepRef | null> }) {
  const { formData } = useTargetFormStore();

  useImperativeHandle(stepRef, () => ({
    handleSave: () => {
      // No-op for the review step as it has no data to save.
    },
    validate: () => true,
  }));

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Review and Confirm</h3>
      <div className="space-y-4 text-gray-300">
        <div><strong>Target Company:</strong> {formData.target}</div>
        <div><strong>Domain/IP:</strong> {formData.domain}</div>
        <div><strong>Primary Target:</strong> {formData.is_primary ? 'Yes' : 'No'}</div>
        <div><strong>Platform:</strong> {formData.platform}</div>
        <div><strong>Login Email:</strong> {formData.login_email}</div>
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
          <strong>Rate Limit:</strong> {formData.rate_limit_requests} requests per {formData.rate_limit_seconds} seconds
        </div>
        <div>
          <strong>Additional Important Info:</strong>
          <ul className="list-disc list-inside ml-4">
            {(formData.additional_info || []).map((item, index) => <li key={index}>{item}</li>)}
          </ul>
        </div>
        <div>
          <strong>Notes:</strong>
          <ul className="list-disc list-inside ml-4">
            {(formData.notes || []).map((item, index) => <li key={index}>{item}</li>)}
          </ul>
        </div>
        <div>
          <strong>Custom Request Headers:</strong>
          <ul className="list-disc list-inside ml-4">
            {(formData.custom_headers || []).map((header, index) => (
              <li key={index}>
                <span className="font-medium">{header.name}:</span> {header.value}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
} 