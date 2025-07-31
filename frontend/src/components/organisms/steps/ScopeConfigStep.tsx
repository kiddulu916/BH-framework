'use client';

import React, { useState, useImperativeHandle } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import ValidationError from '@/components/atoms/ValidationError';
import { 
  validateScopeConfig, 
  getFieldErrors, 
  ValidationError as ValidationErrorType,
  validateScopeUrl
} from '@/lib/validation';
import { Plus, X, HelpCircle } from 'lucide-react';
import { StepRef } from './BasicInfoStep';
import { AlertCircle } from 'lucide-react';

export default function ScopeConfigStep({ stepRef }: { stepRef: React.RefObject<StepRef | null> }) {
  const { formData, updateFormData, setValidationErrors } = useTargetFormStore();
  const [inScope, setInScope] = useState<string[]>(formData.in_scope || []);
  const [outOfScope, setOutOfScope] = useState<string[]>(formData.out_of_scope || []);
  const [newInScope, setNewInScope] = useState('');
  const [newOutOfScope, setNewOutOfScope] = useState('');
  const [validationErrors, setLocalValidationErrors] = useState<ValidationErrorType[]>([]);
  const [showErrors, setShowErrors] = useState(false);
  const [inScopeError, setInScopeError] = useState<string>('');
  const [outOfScopeError, setOutOfScopeError] = useState<string>('');

  const validateAndShowErrors = () => {
    const validation = validateScopeConfig({ in_scope: inScope, out_of_scope: outOfScope });
    setLocalValidationErrors(validation.errors);
    setValidationErrors(validation.errors);
    setShowErrors(true);
    return validation.isValid;
  };

  const validateInputUrl = (url: string): string => {
    if (!url.trim()) return '';
    const error = validateScopeUrl(url);
    return error ? error.message : '';
  };

  const handleInScopeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = rawValue; // No longer using sanitizeUrl
    setNewInScope(sanitizedValue);
    
    // Validate input field
    const error = validateInputUrl(sanitizedValue);
    setInScopeError(error);
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleOutOfScopeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = rawValue; // No longer using sanitizeUrl
    setNewOutOfScope(sanitizedValue);
    
    // Validate input field
    const error = validateInputUrl(sanitizedValue);
    setOutOfScopeError(error);
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleAddInScope = () => {
    if (newInScope.trim() && !inScopeError) {
      setInScope([...inScope, newInScope.trim()]);
      setNewInScope('');
      setInScopeError('');
    }
  };

  const handleRemoveInScope = (index: number) => {
    setInScope(inScope.filter((_, i) => i !== index));
  };

  const handleAddOutOfScope = () => {
    if (newOutOfScope.trim() && !outOfScopeError) {
      setOutOfScope([...outOfScope, newOutOfScope.trim()]);
      setNewOutOfScope('');
      setOutOfScopeError('');
    }
  };

  const handleRemoveOutOfScope = (index: number) => {
    setOutOfScope(outOfScope.filter((_, i) => i !== index));
  };

  useImperativeHandle(stepRef, () => ({
    handleSave: () => {
      const isValid = validateAndShowErrors();
      if (isValid) {
        updateFormData({ in_scope: inScope, out_of_scope: outOfScope });
        // Remove alert popup - just save silently
      }
    },
    validate: () => {
      return validateAndShowErrors();
    },
  }));

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Scope Configuration</h3>
      
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <label className="block text-gray-200 text-sm font-medium">In-Scope URLs</label>
          <div className="group relative">
            <HelpCircle size={16} className="text-gray-400 cursor-help" />
            <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-zinc-900 text-gray-200 text-xs rounded-md opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
              URLs that are approved for testing. Supports wildcards like *.example.com or example.com/api/*
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <Input
            label=""
            placeholder="example.com/api/*"
            value={newInScope}
            onChange={handleInScopeChange}
          />
          <button 
            onClick={handleAddInScope} 
            disabled={!newInScope.trim() || !!inScopeError}
            className="text-gray-400 hover:text-green-500 disabled:text-gray-600 disabled:cursor-not-allowed"
          >
            <Plus size={20} />
          </button>
        </div>
        {inScopeError && (
          <div className="mt-1">
            <div className="flex items-center gap-1 text-red-400 text-sm">
              <AlertCircle size={14} className="flex-shrink-0" />
              <span>{inScopeError}</span>
            </div>
          </div>
        )}
        {showErrors && (
          <div className="mt-1">
            {getFieldErrors(validationErrors, 'in_scope').map((error, index) => (
              <div key={index} className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}
        <div className="mt-2 space-y-2">
          {inScope.map((url, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{url}</span>
              <button onClick={() => handleRemoveInScope(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <label className="block text-gray-200 text-sm font-medium">Out-of-Scope URLs</label>
          <div className="group relative">
            <HelpCircle size={16} className="text-gray-400 cursor-help" />
            <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-zinc-900 text-gray-200 text-xs rounded-md opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
              URLs that are not approved for testing. Supports wildcards like *.example.com or example.com/admin/*
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <Input
            label=""
            placeholder="example.com/admin/*"
            value={newOutOfScope}
            onChange={handleOutOfScopeChange}
          />
          <button 
            onClick={handleAddOutOfScope} 
            disabled={!newOutOfScope.trim() || !!outOfScopeError}
            className="text-gray-400 hover:text-green-500 disabled:text-gray-600 disabled:cursor-not-allowed"
          >
            <Plus size={20} />
          </button>
        </div>
        {outOfScopeError && (
          <div className="mt-1">
            <div className="flex items-center gap-1 text-red-400 text-sm">
              <AlertCircle size={14} className="flex-shrink-0" />
              <span>{outOfScopeError}</span>
            </div>
          </div>
        )}
        {showErrors && (
          <div className="mt-1">
            {getFieldErrors(validationErrors, 'out_of_scope').map((error, index) => (
              <div key={index} className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}
        <div className="mt-2 space-y-2">
          {outOfScope.map((url, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{url}</span>
              <button onClick={() => handleRemoveOutOfScope(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
} 