'use client';

import React, { useState, useImperativeHandle, useEffect } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import ValidationError from '@/components/atoms/ValidationError';
import { 
  validateBasicInfo, 
  getFieldErrors, 
  ValidationError as ValidationErrorType,
  sanitizeTargetCompany,
  sanitizeUrl,
  validateTargetCompany,
  validateDomainUrl
} from '@/lib/utils/validation';
import { AlertCircle } from 'lucide-react';

export interface StepRef {
  handleSave: () => void;
  validate: () => boolean;
}

export default function BasicInfoStep({ stepRef }: { stepRef: React.RefObject<StepRef | null> }) {
  const { formData, updateFormData, setValidationErrors, validationErrors: storeValidationErrors } = useTargetFormStore();
  const [target, setTarget] = useState(formData.target || '');
  const [domain, setDomain] = useState(formData.domain || '');
  const [isPrimary, setIsPrimary] = useState(formData.is_primary || false);
  const [localValidationErrors, setLocalValidationErrors] = useState<ValidationErrorType[]>([]);
  const [showErrors, setShowErrors] = useState(false);

  // Use store validation errors if they exist, otherwise use local ones
  const validationErrors = storeValidationErrors.length > 0 ? storeValidationErrors : localValidationErrors;

  const targetId = 'input-target-company';
  const domainId = 'input-domain-ip';

  // Clear errors when user starts typing
  const handleTargetChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = sanitizeTargetCompany(rawValue);
    setTarget(sanitizedValue);
    updateFormData({ target: sanitizedValue, domain, is_primary: isPrimary });
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleDomainChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = sanitizeUrl(rawValue);
    setDomain(sanitizedValue);
    updateFormData({ target, domain: sanitizedValue, is_primary: isPrimary });
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handlePrimaryChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.checked;
    setIsPrimary(value);
    updateFormData({ target, domain, is_primary: value });
  };

  const validateAndShowErrors = () => {
    const validation = validateBasicInfo({ target, domain, is_primary: isPrimary });
    setLocalValidationErrors(validation.errors);
    setValidationErrors(validation.errors);
    setShowErrors(true);
    return validation.isValid;
  };

  useImperativeHandle(stepRef, () => ({
    handleSave: () => {
      const isValid = validateAndShowErrors();
      if (isValid) {
        updateFormData({ target, domain, is_primary: isPrimary });
        // Remove alert popup - just save silently
      }
    },
    validate: () => {
      return validateAndShowErrors();
    },
  }));

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Build Target Profile</h3>
      
      <div className="mb-6">
        <label htmlFor={targetId} className="block text-gray-200 text-sm font-medium mb-2">Target Company</label>
        <Input
          id={targetId}
          label=""
          placeholder="Enter target company name"
          value={target}
          onChange={handleTargetChange}
          required
        />
        {(showErrors || storeValidationErrors.length > 0) && (
          <div className="mt-1">
            {getFieldErrors(validationErrors, 'Target Company').map((error, index) => (
              <div key={index} className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="mb-6">
        <label htmlFor={domainId} className="block text-gray-200 text-sm font-medium mb-2">Domain/IP Address</label>
        <Input
          id={domainId}
          label=""
          placeholder="Enter domain or IP address"
          value={domain}
          onChange={handleDomainChange}
          required
        />
        {(showErrors || storeValidationErrors.length > 0) && (
          <div className="mt-1">
            {getFieldErrors(validationErrors, 'Domain/IP Address').map((error, index) => (
              <div key={index} className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="mb-6">
        <label className="flex items-center space-x-2 text-gray-200">
          <input
            type="checkbox"
            checked={isPrimary}
            onChange={handlePrimaryChange}
            className="rounded border-gray-600 bg-zinc-800 text-green-500 focus:ring-green-500"
          />
          <span>Set as Primary Target</span>
        </label>
      </div>

    </div>
  );
} 