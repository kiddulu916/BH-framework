'use client';

import React, { useState, useImperativeHandle, useEffect } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import ValidationError from '@/components/atoms/ValidationError';
import { 
  validateBasicInfo, 
  getFieldErrors, 
  ValidationError as ValidationErrorType,
  validateTargetCompany,
  validateDomain
} from '@/lib/validation';
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
    const value = e.target.value;
    setTarget(value);
    updateFormData({ target: value, domain, is_primary: isPrimary });
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleDomainChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setDomain(value);
    updateFormData({ target, domain: value, is_primary: isPrimary });
    
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
    <div className="space-y-6">
      <div>
        <h3 className="text-4xl font-bold text-white text-center mb-8">Basic Information</h3>
        <p className="text-gray-300 text-center mb-8">
          Enter the basic information about your target
        </p>
      </div>

      <div className="space-y-6">
        {/* Target Company */}
        <div>
          <Input
            id={targetId}
            label="Target Company"
            placeholder="Enter target company name"
            value={target}
            onChange={handleTargetChange}
            required
            error={showErrors ? getFieldErrors(validationErrors, 'Target Company')[0] : undefined}
          />
        </div>

        {/* Domain/IP Address */}
        <div>
          <Input
            id={domainId}
            label="Domain/IP Address"
            placeholder="Enter domain or IP address"
            value={domain}
            onChange={handleDomainChange}
            required
            error={showErrors ? getFieldErrors(validationErrors, 'domain')[0] : undefined}
          />
        </div>

        {/* Primary Target Checkbox */}
        <div className="flex items-center space-x-3">
          <input
            type="checkbox"
            id="primary-target"
            checked={isPrimary}
            onChange={handlePrimaryChange}
            className="w-4 h-4 text-blue-600 bg-zinc-800 border-zinc-700 rounded focus:ring-blue-500 focus:ring-2"
          />
          <label htmlFor="primary-target" className="text-gray-200 text-sm">
            Mark as primary target
          </label>
        </div>

        {/* Validation Errors */}
        {showErrors && validationErrors.length > 0 && (
          <div className="bg-red-900/20 border border-red-500/50 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertCircle size={16} className="text-red-400" />
              <span className="text-red-400 font-medium">Please fix the following errors:</span>
            </div>
            <ValidationError 
              errors={validationErrors.map(error => `${error.field}: ${error.message}`)} 
              className="text-red-300"
            />
          </div>
        )}
      </div>
    </div>
  );
} 