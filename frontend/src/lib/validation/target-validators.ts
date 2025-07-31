import { TargetCreateRequest, CustomHeader, ValidationError, ValidationResult } from './types';
import { validateList } from './helpers';
import {
  validateTargetCompany,
  validateDomain,
  validateEmail,
  validateHeaderName,
  validateHeaderValue,
  validateRateLimit,
  validateScopeUrl,
  validateTextInfo
} from './validators';

// ---- High-level validators ------------------------------------------------

/**
 * Validates a custom header with both name and value validation
 */
export const validateCustomHeader = (header: CustomHeader): ValidationError | null => {
  const nameError = validateHeaderName(header.name);
  if (nameError) return nameError;
  
  const valueError = validateHeaderValue(header.value);
  if (valueError) return valueError;
  
  return null;
};

/**
 * Validates basic target information (target name and domain)
 */
export const validateBasicInfo = (formData: Partial<TargetCreateRequest> & { name?: string; value?: string }): ValidationResult => {
  const errors: ValidationError[] = [];
  
  // Validate target name - handle legacy field names
  const targetName = formData.target || formData.name || '';
  const targetError = validateTargetCompany(targetName);
  if (targetError) errors.push(targetError);
  
  // Validate domain - handle legacy field names
  const domainValue = formData.domain || formData.value || '';
  const domainError = validateDomain(domainValue);
  if (domainError) errors.push(domainError);
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Validates program details (emails)
 */
export const validateProgramDetails = (formData: Partial<TargetCreateRequest> & { platform_email?: string; researcher_email?: string }): ValidationResult => {
  const errors: ValidationError[] = [];
  
  // Validate platform email
  const platformEmailError = validateEmail(formData.platform_email || formData.login_email || '');
  if (platformEmailError) errors.push(platformEmailError);
  
  // Validate researcher email
  const researcherEmailError = validateEmail(formData.researcher_email || '');
  if (researcherEmailError) errors.push(researcherEmailError);
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Validates scope configuration (in-scope and out-of-scope URLs)
 */
export const validateScopeConfig = (formData: Partial<TargetCreateRequest> & { in_scope?: string[]; out_of_scope?: string[] }): ValidationResult => {
  const errors: ValidationError[] = [];
  
  // Use generic list validation for in-scope URLs
  errors.push(...validateList(
    formData.in_scope,
    validateScopeUrl,
    'in_scope'
  ));
  
  // Use generic list validation for out-of-scope URLs
  errors.push(...validateList(
    formData.out_of_scope,
    validateScopeUrl,
    'out_of_scope'
  ));
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Validates additional information (custom headers, additional info, notes)
 */
export const validateAdditionalInfo = (formData: Partial<TargetCreateRequest> & { custom_headers?: CustomHeader[] }): ValidationResult => {
  const errors: ValidationError[] = [];
  
  // Validate additional_info - only validate if not empty
  const additionalInfo = formData.additional_info || [];
  additionalInfo.forEach((info, index) => {
    if (info && info.trim()) {
      const infoError = validateTextInfo(info);
      if (infoError) {
        errors.push({ field: `additional_info_${index}`, message: `Additional info ${index + 1}: ${infoError.message}` });
      }
    }
  });
  
  // Validate notes - only validate if not empty
  const notes = formData.notes || [];
  notes.forEach((note, index) => {
    if (note && note.trim()) {
      const noteError = validateTextInfo(note);
      if (noteError) {
        errors.push({ field: `notes_${index}`, message: `Note ${index + 1}: ${noteError.message}` });
      }
    }
  });
  
  // Use generic list validation for custom headers
  errors.push(...validateList(
    formData.custom_headers,
    validateCustomHeader,
    'custom_header'
  ));
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Validates rate limiting configuration
 */
export const validateRateLimiting = (formData: Partial<TargetCreateRequest> & { rate_limit_requests?: number; rate_limit_seconds?: number }): ValidationResult => {
  const errors: ValidationError[] = [];
  
  // Only validate if rate limits are provided
  if (formData.rate_limit_requests !== undefined || formData.rate_limit_seconds !== undefined) {
    const rateLimitError = validateRateLimit(
      formData.rate_limit_requests,
      formData.rate_limit_seconds
    );
    if (rateLimitError) errors.push(rateLimitError);
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Complete form validation using all validation functions
 */
export const validateCompleteForm = (formData: Partial<TargetCreateRequest>): ValidationResult => {
  const errors: ValidationError[] = [];
  
  // Run all validation functions
  const basicInfoResult = validateBasicInfo(formData);
  const programDetailsResult = validateProgramDetails(formData);
  const scopeConfigResult = validateScopeConfig(formData);
  const additionalInfoResult = validateAdditionalInfo(formData);
  const rateLimitingResult = validateRateLimiting(formData);
  
  // Combine all errors
  errors.push(...basicInfoResult.errors);
  errors.push(...programDetailsResult.errors);
  errors.push(...scopeConfigResult.errors);
  errors.push(...additionalInfoResult.errors);
  errors.push(...rateLimitingResult.errors);
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Helper functions for backward compatibility
export const getFieldErrors = (errors: ValidationError[], fieldName: string): string[] => {
  return errors
    .filter(error => error.field === fieldName)
    .map(error => error.message);
};

export const formatValidationErrors = (errors: ValidationError[]): string[] => {
  return errors.map(error => `${error.field}: ${error.message}`);
};

// Alias for backward compatibility
export const validateAdditionalRules = validateAdditionalInfo;