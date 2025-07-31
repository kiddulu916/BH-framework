import { ValidationError } from './types';
import { 
  containsMalicious, 
  isValidDomain, 
  isValidURL, 
  isValidEmail, 
  isValidHeaderName, 
  isValidHeaderValue 
} from './helpers';

// ---- Field-level validators ----------------------------------------------

/**
 * Validates a domain string with RFC compliance
 * Supports IDN/punycode and proper TLD requirements
 */
export const validateDomain = (value: string): ValidationError | null => {
  if (!value?.trim()) return null; // Domain is optional
  
  if (containsMalicious(value)) {
    return { field: 'domain', message: 'Domain contains malicious patterns' };
  }
  
  if (!isValidDomain(value)) {
    return { field: 'domain', message: 'Invalid domain format' };
  }
  
  return null;
};

/**
 * Validates a URL string with RFC compliance
 * Supports proper protocols and TLD requirements
 */
export const validateURL = (value: string): ValidationError | null => {
  if (!value?.trim()) return null; // URL is optional
  
  if (containsMalicious(value)) {
    return { field: 'url', message: 'URL contains malicious patterns' };
  }
  
  if (!isValidURL(value)) {
    return { field: 'url', message: 'Invalid URL format' };
  }
  
  return null;
};

/**
 * Validates an email address with RFC compliance
 */
export const validateEmail = (email: string): ValidationError | null => {
  if (!email?.trim()) return null; // Email is optional
  
  if (containsMalicious(email)) {
    return { field: 'email', message: 'Email contains malicious patterns' };
  }
  
  if (!isValidEmail(email)) {
    return { field: 'email', message: 'Invalid email format' };
  }
  
  return null;
};

/**
 * Validates HTTP header name per RFC 7230
 * Allows all valid token characters: !#$%&'*+.^_`|~ + alphanumeric
 */
export const validateHeaderName = (value: string): ValidationError | null => {
  if (!value?.trim()) {
    return { field: 'header_name', message: 'Header name is required' };
  }
  
  if (containsMalicious(value)) {
    return { field: 'header_name', message: 'Header name contains malicious patterns' };
  }
  
  if (!isValidHeaderName(value)) {
    return { field: 'header_name', message: 'Header name contains invalid characters' };
  }
  
  return null;
};

/**
 * Validates HTTP header value with security checks
 * Allows visible ASCII + common UTF-8 characters
 */
export const validateHeaderValue = (value: string): ValidationError | null => {
  if (!value?.trim()) {
    return { field: 'header_value', message: 'Header value is required' };
  }
  
  if (containsMalicious(value)) {
    return { field: 'header_value', message: 'Header value contains malicious patterns' };
  }
  
  if (!isValidHeaderValue(value)) {
    return { field: 'header_value', message: 'Header value contains invalid characters' };
  }
  
  return null;
};

/**
 * Validates rate limit parameters with proper edge case handling
 * Treats undefined as "not set" rather than invalid
 */
export const validateRateLimit = (requests?: number, seconds?: number): ValidationError | null => {
  // If both are undefined, it's not set
  if (requests == null && seconds == null) return null;
  
  // If only one is set, validate the set one
  if (requests != null && (requests <= 0)) {
    return { field: 'rate_limit_requests', message: 'Requests must be greater than 0' };
  }
  
  if (seconds != null && (seconds <= 0)) {
    return { field: 'rate_limit_seconds', message: 'Seconds must be greater than 0' };
  }
  
  return null;
};

/**
 * Validates required fields with proper handling of falsy values
 * Explicitly tests for null/undefined rather than treating 0/false as invalid
 */
export const validateRequired = (value: unknown, fieldName: string): ValidationError | null => {
  if (value == null) {
    return { field: fieldName, message: `${fieldName} is required` };
  }
  
  if (typeof value === 'string' && value.trim() === '') {
    return { field: fieldName, message: `${fieldName} is required` };
  }
  
  return null;
};

/**
 * Validates target company name with security checks
 * Allows letters, numbers, spaces, and common company name characters
 */
export const validateTargetCompany = (value: string): ValidationError | null => {
  if (!value?.trim()) {
    return { field: 'Target Company', message: 'Target Company is required' };
  }
  
  if (containsMalicious(value)) {
    return { field: 'Target Company', message: 'Target Company contains malicious patterns' };
  }
  
  // Allow letters, numbers, spaces, and common company name characters
  const allowedPattern = /^[A-Za-z0-9\s@.&,\-()]+$/;
  if (!allowedPattern.test(value)) {
    return { field: 'Target Company', message: 'Target Company can only contain letters, numbers, spaces, and common punctuation' };
  }
  
  return null;
};

/**
 * Validates scope URL with support for wildcards and protocols
 */
export const validateScopeUrl = (value: string): ValidationError | null => {
  if (!value?.trim()) {
    return { field: 'scope_url', message: 'URL is required' };
  }
  
  if (containsMalicious(value)) {
    return { field: 'scope_url', message: 'URL contains malicious patterns' };
  }
  
  // Handle wildcard domains
  if (value === '*' || value.startsWith('*.')) {
    return null;
  }
  
  // Handle URLs with protocols
  if (value.includes('://')) {
    const urlParts = value.split('://');
    if (urlParts.length !== 2 || !urlParts[0] || !urlParts[1]) {
      return { field: 'scope_url', message: 'Invalid URL format' };
    }
    
    const protocol = urlParts[0].toLowerCase();
    if (protocol !== 'http' && protocol !== 'https' && protocol !== '*') {
      return { field: 'scope_url', message: 'Invalid URL protocol' };
    }
    
    // Validate the domain part
    const domainPart = urlParts[1].split('/')[0];
    if (!isValidDomain(domainPart)) {
      return { field: 'scope_url', message: 'Invalid domain in URL' };
    }
  } else {
    // No protocol - should be a valid domain
    if (!isValidDomain(value)) {
      return { field: 'scope_url', message: 'Invalid domain format' };
    }
  }
  
  return null;
};

/**
 * Validates text information with security checks
 * Allows letters, spaces, and specific special characters
 */
export const validateTextInfo = (value: string): ValidationError | null => {
  if (!value?.trim()) return null; // Text info is optional
  
  if (containsMalicious(value)) {
    return { field: 'text_info', message: 'Text contains malicious patterns' };
  }
  
  // Allow letters, spaces, and specific special characters: ., ,, ", ', :, -, /
  const textPattern = /^[A-Za-z\s.,"'":\-/]+$/;
  if (!textPattern.test(value)) {
    return { field: 'text_info', message: 'Text can only contain letters, spaces, and ., ,, ", \', :, -, /' };
  }
  
  return null;
};