'use client';

import React, { useState, useImperativeHandle } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import Input from '@/components/atoms/Input';
import ValidationError from '@/components/atoms/ValidationError';
import { 
  validateAdditionalInfo, 
  getFieldErrors, 
  ValidationError as ValidationErrorType,
  validateHeaderName,
  validateHeaderValue,
  validateTextInfo
} from '@/lib/validation';
import { Plus, X, HelpCircle } from 'lucide-react';
import { StepRef } from './BasicInfoStep';
import { CustomHeader } from '@/types/target';
import { AlertCircle } from 'lucide-react';

export default function AdditionalInfoStep({ stepRef }: { stepRef: React.RefObject<StepRef | null> }) {
  const { formData, updateFormData, setValidationErrors } = useTargetFormStore();
  const [additionalInfo, setAdditionalInfo] = useState<string[]>(formData.additional_info || []);
  const [notes, setNotes] = useState<string[]>(formData.notes || []);
  const [customHeaders, setCustomHeaders] = useState<CustomHeader[]>(formData.custom_headers || []);
  const [newAdditionalInfo, setNewAdditionalInfo] = useState('');
  const [newNote, setNewNote] = useState('');
  const [newHeaderName, setNewHeaderName] = useState('');
  const [newHeaderValue, setNewHeaderValue] = useState('');
  const [validationErrors, setLocalValidationErrors] = useState<ValidationErrorType[]>([]);
  const [showErrors, setShowErrors] = useState(false);
  const [headerNameError, setHeaderNameError] = useState<string>('');
  const [headerValueError, setHeaderValueError] = useState<string>('');
  const [additionalInfoError, setAdditionalInfoError] = useState<string>('');
  const [noteError, setNoteError] = useState<string>('');

  const validateAndShowErrors = () => {
    const validation = validateAdditionalInfo({ 
      additional_info: additionalInfo, 
      notes: notes,
      custom_headers: customHeaders 
    });
    setLocalValidationErrors(validation.errors);
    setValidationErrors(validation.errors);
    setShowErrors(true);
    // Always return true for this step since additional info and notes are optional
    return true;
  };

  const validateInputText = (text: string): string => {
    if (!text.trim()) return '';
    const error = validateTextInfo(text);
    return error ? error.message : '';
  };

  const handleHeaderNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = rawValue; // No sanitization needed here as per new validation
    setNewHeaderName(sanitizedValue);
    
    // Validate input field
    const error = validateHeaderName(sanitizedValue);
    setHeaderNameError(error ? error.message : '');
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleHeaderValueChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = rawValue; // No sanitization needed here as per new validation
    setNewHeaderValue(sanitizedValue);
    
    // Validate input field
    const error = validateHeaderValue(sanitizedValue);
    setHeaderValueError(error ? error.message : '');
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleAdditionalInfoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = rawValue; // No sanitization needed here as per new validation
    setNewAdditionalInfo(sanitizedValue);
    
    // Validate input field
    const error = validateInputText(sanitizedValue);
    setAdditionalInfoError(error);
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleNoteChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const rawValue = e.target.value;
    const sanitizedValue = rawValue; // No sanitization needed here as per new validation
    setNewNote(sanitizedValue);
    
    // Validate input field
    const error = validateInputText(sanitizedValue);
    setNoteError(error);
    
    // Clear errors when user starts typing
    if (showErrors) {
      setShowErrors(false);
      setLocalValidationErrors([]);
      setValidationErrors([]);
    }
  };

  const handleAddAdditionalInfo = () => {
    if (newAdditionalInfo.trim() && !additionalInfoError) {
      setAdditionalInfo([...additionalInfo, newAdditionalInfo.trim()]);
      setNewAdditionalInfo('');
      setAdditionalInfoError('');
    }
  };

  const handleRemoveAdditionalInfo = (index: number) => {
    setAdditionalInfo(additionalInfo.filter((_, i) => i !== index));
  };

  const handleAddNote = () => {
    if (newNote.trim() && !noteError) {
      setNotes([...notes, newNote.trim()]);
      setNewNote('');
      setNoteError('');
    }
  };

  const handleRemoveNote = (index: number) => {
    setNotes(notes.filter((_, i) => i !== index));
  };

  const handleAddCustomHeader = () => {
    if (newHeaderName.trim() && newHeaderValue.trim() && !headerNameError && !headerValueError) {
      const newHeader: CustomHeader = {
        name: newHeaderName.trim() + ':', // Add colon at the end
        value: newHeaderValue.trim(),
      };
      setCustomHeaders([...customHeaders, newHeader]);
      setNewHeaderName('');
      setNewHeaderValue('');
      setHeaderNameError('');
      setHeaderValueError('');
    }
  };

  const handleRemoveCustomHeader = (index: number) => {
    setCustomHeaders(customHeaders.filter((_, i) => i !== index));
  };

  useImperativeHandle(stepRef, () => ({
    handleSave: () => {
      const isValid = validateAndShowErrors();
      if (isValid) {
        updateFormData({ 
          additional_info: additionalInfo, 
          notes: notes,
          custom_headers: customHeaders
        });
        // Remove alert popup - just save silently
      }
    },
    validate: () => {
      return validateAndShowErrors();
    },
  }));

  return (
    <div>
      <h3 className="text-4xl font-bold text-white text-center mb-8">Headers, Notes, & Info</h3>
      
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <label className="block text-gray-200 text-sm font-medium">Custom Request Headers</label>
          <div className="group relative">
            <HelpCircle size={16} className="text-gray-400 cursor-help" />
            <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-zinc-900 text-gray-200 text-xs rounded-md opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
              Headers that need to be included with every request to the target's web pages
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <div className="flex items-center gap-2 flex-1">
            <Input
              label=""
              placeholder="Header name (e.g. Authorization, User-Agent)"
              value={newHeaderName}
              onChange={handleHeaderNameChange}
            />
            <Input
              label=""
              placeholder="Header value"
              value={newHeaderValue}
              onChange={handleHeaderValueChange}
            />
            <button 
              onClick={handleAddCustomHeader} 
              disabled={!newHeaderName.trim() || !newHeaderValue.trim() || !!headerNameError || !!headerValueError}
              className="text-gray-400 hover:text-green-500 disabled:text-gray-600 disabled:cursor-not-allowed"
            >
              <Plus size={20} />
            </button>
          </div>
        </div>
        {(headerNameError || headerValueError) && (
          <div className="mt-1 space-y-1">
            {headerNameError && (
              <div className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{headerNameError}</span>
              </div>
            )}
            {headerValueError && (
              <div className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{headerValueError}</span>
              </div>
            )}
          </div>
        )}
        {showErrors && (
          <div className="mt-1">
            {getFieldErrors(validationErrors, 'custom_header').map((error, index) => (
              <div key={index} className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}
        <div className="mt-2 space-y-2">
          {customHeaders.map((header, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <div className="flex flex-col">
                <span className="text-gray-100 font-medium">{header.name}</span>
                <span className="text-gray-400 text-sm">{header.value}</span>
              </div>
              <button onClick={() => handleRemoveCustomHeader(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>
      
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <label className="block text-gray-200 text-sm font-medium">Additional Important Info</label>
          <div className="group relative">
            <HelpCircle size={16} className="text-gray-400 cursor-help" />
            <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-zinc-900 text-gray-200 text-xs rounded-md opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
              Important information about testing restrictions or requirements
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <Input
            label=""
            placeholder="e.g. Do not test during business hours"
            value={newAdditionalInfo}
            onChange={handleAdditionalInfoChange}
          />
          <button 
            onClick={handleAddAdditionalInfo} 
            disabled={!newAdditionalInfo.trim() || !!additionalInfoError}
            className="text-gray-400 hover:text-green-500 disabled:text-gray-600 disabled:cursor-not-allowed"
          >
            <Plus size={20} />
          </button>
        </div>
        {additionalInfoError && (
          <div className="mt-1">
            <div className="flex items-center gap-1 text-red-400 text-sm">
              <AlertCircle size={14} className="flex-shrink-0" />
              <span>{additionalInfoError}</span>
            </div>
          </div>
        )}
        {showErrors && (
          <div className="mt-1">
            {getFieldErrors(validationErrors, 'additional_info').map((error, index) => (
              <div key={index} className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}
        <div className="mt-2 space-y-2">
          {additionalInfo.map((info, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{info}</span>
              <button onClick={() => handleRemoveAdditionalInfo(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <label className="block text-gray-200 text-sm font-medium">Notes</label>
          <div className="group relative">
            <HelpCircle size={16} className="text-gray-400 cursor-help" />
            <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-zinc-900 text-gray-200 text-xs rounded-md opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
              Additional notes about testing restrictions or requirements
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <Input
            label=""
            placeholder="e.g. Do not perform DDoS attacks"
            value={newNote}
            onChange={handleNoteChange}
          />
          <button 
            onClick={handleAddNote} 
            disabled={!newNote.trim() || !!noteError}
            className="text-gray-400 hover:text-green-500 disabled:text-gray-600 disabled:cursor-not-allowed"
          >
            <Plus size={20} />
          </button>
        </div>
        {noteError && (
          <div className="mt-1">
            <div className="flex items-center gap-1 text-red-400 text-sm">
              <AlertCircle size={14} className="flex-shrink-0" />
              <span>{noteError}</span>
            </div>
          </div>
        )}
        {showErrors && (
          <div className="mt-1">
            {getFieldErrors(validationErrors, 'notes').map((error, index) => (
              <div key={index} className="flex items-center gap-1 text-red-400 text-sm">
                <AlertCircle size={14} className="flex-shrink-0" />
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}
        <div className="mt-2 space-y-2">
          {notes.map((note, index) => (
            <div key={index} className="flex items-center justify-between bg-zinc-800 p-2 rounded-md">
              <span className="text-gray-100">{note}</span>
              <button onClick={() => handleRemoveNote(index)} className="text-gray-400 hover:text-red-500">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
} 