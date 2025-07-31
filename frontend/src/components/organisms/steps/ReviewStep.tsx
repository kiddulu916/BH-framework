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
      <div className="space-y-6 text-gray-300 max-h-[60vh] overflow-y-auto pr-2">
        {/* Basic Information */}
        <div className="bg-zinc-700/50 rounded-lg p-4">
          <h4 className="text-lg font-semibold text-white mb-3">Basic Information</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div><strong>Target Company:</strong> {formData.target || 'Not specified'}</div>
            <div><strong>Domain/IP:</strong> {formData.domain || 'Not specified'}</div>
            <div><strong>Primary Target:</strong> {formData.is_primary ? 'Yes' : 'No'}</div>
            <div><strong>Platform:</strong> {formData.platform || 'Not specified'}</div>
          </div>
        </div>

        {/* Contact Information */}
        <div className="bg-zinc-700/50 rounded-lg p-4">
          <h4 className="text-lg font-semibold text-white mb-3">Contact Information</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div><strong>Login Email:</strong> {formData.login_email || 'Not specified'}</div>
            <div><strong>Researcher Email:</strong> {formData.researcher_email || 'Not specified'}</div>
          </div>
        </div>

        {/* Scope Configuration */}
        <div className="bg-zinc-700/50 rounded-lg p-4">
          <h4 className="text-lg font-semibold text-white mb-3">Scope Configuration</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <strong>In Scope:</strong>
              {(formData.in_scope && formData.in_scope.length > 0) ? (
                <ul className="list-disc list-inside ml-4 mt-1">
                  {formData.in_scope.map((item, index) => <li key={index}>{item}</li>)}
                </ul>
              ) : (
                <span className="text-gray-400 ml-2">None specified</span>
              )}
            </div>
            <div>
              <strong>Out of Scope:</strong>
              {(formData.out_of_scope && formData.out_of_scope.length > 0) ? (
                <ul className="list-disc list-inside ml-4 mt-1">
                  {formData.out_of_scope.map((item, index) => <li key={index}>{item}</li>)}
                </ul>
              ) : (
                <span className="text-gray-400 ml-2">None specified</span>
              )}
            </div>
          </div>
        </div>

        {/* Rate Limiting */}
        <div className="bg-zinc-700/50 rounded-lg p-4">
          <h4 className="text-lg font-semibold text-white mb-3">Rate Limiting</h4>
          <div>
            <strong>Rate Limit:</strong> {formData.rate_limit_requests || 0} requests per {formData.rate_limit_seconds || 0} seconds
          </div>
        </div>

        {/* Custom Headers */}
        <div className="bg-zinc-700/50 rounded-lg p-4">
          <h4 className="text-lg font-semibold text-white mb-3">Custom Headers</h4>
          <div>
            <strong>Custom Headers:</strong>
            {(formData.custom_headers && formData.custom_headers.length > 0) ? (
              <ul className="list-disc list-inside ml-4 mt-1">
                {formData.custom_headers.map((header, index) => (
                  <li key={index}>{header.name} {header.value}</li>
                ))}
              </ul>
            ) : (
              <span className="text-gray-400 ml-2">None specified</span>
            )}
          </div>
        </div>

        {/* Additional Information */}
        <div className="bg-zinc-700/50 rounded-lg p-4">
          <h4 className="text-lg font-semibold text-white mb-3">Additional Information</h4>
          <div>
            <strong>Additional Important Info:</strong>
            {(formData.additional_info && formData.additional_info.length > 0) ? (
              <ul className="list-disc list-inside ml-4 mt-1">
                {formData.additional_info.map((item, index) => <li key={index}>{item}</li>)}
              </ul>
            ) : (
              <span className="text-gray-400 ml-2">None specified</span>
            )}
          </div>
        </div>

        {/* Notes */}
        <div className="bg-zinc-700/50 rounded-lg p-4">
          <h4 className="text-lg font-semibold text-white mb-3">Notes</h4>
          <div>
            <strong>Notes:</strong>
            {(formData.notes && formData.notes.length > 0) ? (
              <ul className="list-disc list-inside ml-4 mt-1">
                {formData.notes.map((item, index) => <li key={index}>{item}</li>)}
              </ul>
            ) : (
              <span className="text-gray-400 ml-2">None specified</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
} 