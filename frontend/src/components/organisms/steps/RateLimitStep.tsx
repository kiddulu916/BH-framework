'use client';

import React, { useState, useImperativeHandle, useEffect } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import ValidationError from '@/components/atoms/ValidationError';
import { validateRateLimiting, getFieldErrors, ValidationError as ValidationErrorType } from '@/lib/validation';
import { StepRef } from './BasicInfoStep';

export default function RateLimitStep({ stepRef }: { stepRef: React.RefObject<StepRef | null> }) {
  const { formData, updateFormData, setValidationErrors } = useTargetFormStore();
  const [maxRequests, setMaxRequests] = useState(formData.rate_limit_requests || 0);
  const [timeSeconds, setTimeSeconds] = useState(formData.rate_limit_seconds || 0);
  const [validationErrors, setLocalValidationErrors] = useState<ValidationErrorType[]>([]);
  const [touched, setTouched] = useState<{ maxRequests: boolean; timeSeconds: boolean }>({ maxRequests: false, timeSeconds: false });

  // Real-time validation
  useEffect(() => {
    const validation = validateRateLimiting({ 
      rate_limit_requests: maxRequests, 
      rate_limit_seconds: timeSeconds 
    });
    if (!validation.isValid) {
      setLocalValidationErrors(validation.errors);
      setValidationErrors(validation.errors);
    } else {
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  }, [maxRequests, timeSeconds, setValidationErrors]);

  const handleMaxRequestsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = parseInt(e.target.value) || 0;
    setMaxRequests(value);
    updateFormData({ rate_limit_requests: value });
    setTouched((prev) => ({ ...prev, maxRequests: true }));
  };

  const handleTimeSecondsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = parseInt(e.target.value) || 0;
    setTimeSeconds(value);
    updateFormData({ rate_limit_seconds: value });
    setTouched((prev) => ({ ...prev, timeSeconds: true }));
  };

  useImperativeHandle(stepRef, () => ({
    handleSave: () => {
      const validation = validateRateLimiting({ 
        rate_limit_requests: maxRequests, 
        rate_limit_seconds: timeSeconds 
      });
      if (validation.isValid) {
        updateFormData({ rate_limit_requests: maxRequests, rate_limit_seconds: timeSeconds });
        alert('Step 4 data saved!');
      } else {
        setLocalValidationErrors(validation.errors);
        alert('Please fix validation errors before saving.');
      }
    },
    validate: () => {
      const validation = validateRateLimiting({ 
        rate_limit_requests: maxRequests, 
        rate_limit_seconds: timeSeconds 
      });
      return validation.isValid;
    },
  }));

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Rate Limiting</h3>
      
      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Max Requests</label>
        <Input
          label=""
          type="number"
          placeholder="Enter maximum requests allowed"
          value={String(maxRequests)}
          onChange={handleMaxRequestsChange}
          min="0"
          onBlur={() => setTouched((prev) => ({ ...prev, maxRequests: true }))}
        />
        {touched.maxRequests && (
          <ValidationError errors={getFieldErrors(validationErrors, 'rate_limit_requests')} />
        )}
      </div>

      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Time (seconds)</label>
        <Input
          label=""
          type="number"
          placeholder="Enter time period in seconds"
          value={String(timeSeconds)}
          onChange={handleTimeSecondsChange}
          min="0"
          onBlur={() => setTouched((prev) => ({ ...prev, timeSeconds: true }))}
        />
        {touched.timeSeconds && (
          <ValidationError errors={getFieldErrors(validationErrors, 'rate_limit_seconds')} />
        )}
      </div>
    </div>
  );
} 