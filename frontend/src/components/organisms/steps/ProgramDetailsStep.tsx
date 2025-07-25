'use client';

import React, { useState, useImperativeHandle, useEffect } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import Select from '@/components/atoms/Select';
import ValidationError from '@/components/atoms/ValidationError';
import { validateProgramDetails, getFieldErrors, ValidationError as ValidationErrorType } from '@/lib/utils/validation';
import { BugBountyPlatform } from '@/types/target';
import { StepRef } from './BasicInfoStep';

export default function ProgramDetailsStep({ stepRef }: { stepRef: React.RefObject<StepRef | null> }) {
  const { formData, updateFormData, setValidationErrors } = useTargetFormStore();
  const [platform, setPlatform] = useState<BugBountyPlatform>(formData.platform || BugBountyPlatform.HACKERONE);
  const [loginEmail, setLoginEmail] = useState(formData.login_email || '');
  const [researcherEmail, setResearcherEmail] = useState(formData.researcher_email || '');
  const [validationErrors, setLocalValidationErrors] = useState<ValidationErrorType[]>([]);
  const [touched, setTouched] = useState<{ loginEmail: boolean; researcherEmail: boolean }>({ loginEmail: false, researcherEmail: false });

  // Real-time validation
  useEffect(() => {
    const validation = validateProgramDetails({ 
      login_email: loginEmail, 
      researcher_email: researcherEmail 
    });
    if (!validation.isValid) {
      setLocalValidationErrors(validation.errors);
      setValidationErrors(validation.errors);
    } else {
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  }, [loginEmail, researcherEmail, setValidationErrors]);

  const handlePlatformChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const value = e.target.value as BugBountyPlatform;
    setPlatform(value);
    updateFormData({ platform: value });
  };

  const handleLoginEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setLoginEmail(value);
    updateFormData({ login_email: value });
    setTouched((prev) => ({ ...prev, loginEmail: true }));
  };

  const handleResearcherEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setResearcherEmail(value);
    updateFormData({ researcher_email: value });
    setTouched((prev) => ({ ...prev, researcherEmail: true }));
  };

  useImperativeHandle(stepRef, () => ({
    handleSave: () => {
      const validation = validateProgramDetails({ 
        login_email: loginEmail, 
        researcher_email: researcherEmail 
      });
      if (validation.isValid) {
        updateFormData({ platform, login_email: loginEmail, researcher_email: researcherEmail });
        alert('Step 2 data saved!');
      } else {
        setLocalValidationErrors(validation.errors);
        alert('Please fix validation errors before saving.');
      }
    },
    validate: () => {
      const validation = validateProgramDetails({ 
        login_email: loginEmail, 
        researcher_email: researcherEmail 
      });
      return validation.isValid;
    },
  }));

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Program Details</h3>
      
      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Bug Bounty Platform</label>
        <Select
          label=""
          value={platform}
          onChange={handlePlatformChange}
          options={[
            { value: BugBountyPlatform.HACKERONE, label: 'HackerOne' },
            { value: BugBountyPlatform.BUGCROWD, label: 'Bugcrowd' },
            { value: BugBountyPlatform.INTIGRITI, label: 'Intigriti' },
            { value: BugBountyPlatform.YESWEHACK, label: 'YesWeHack' },
            { value: BugBountyPlatform.CUSTOM, label: 'Custom' },
          ]}
        />
      </div>

      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Login Email</label>
        <Input
          label=""
          placeholder="Enter your login email for the platform"
          value={loginEmail}
          onChange={handleLoginEmailChange}
          title="Email address used to log into the bug bounty platform"
          onBlur={() => setTouched((prev) => ({ ...prev, loginEmail: true }))}
        />
        {touched.loginEmail && (
          <ValidationError errors={getFieldErrors(validationErrors, 'login_email')} />
        )}
      </div>

      <div className="mb-6">
        <label className="block text-gray-200 text-sm font-medium mb-2">Researcher Email</label>
        <Input
          label=""
          placeholder="Enter your researcher email"
          value={researcherEmail}
          onChange={handleResearcherEmailChange}
          title="Email address associated with your researcher profile"
          onBlur={() => setTouched((prev) => ({ ...prev, researcherEmail: true }))}
        />
        {touched.researcherEmail && (
          <ValidationError errors={getFieldErrors(validationErrors, 'researcher_email')} />
        )}
      </div>
    </div>
  );
} 