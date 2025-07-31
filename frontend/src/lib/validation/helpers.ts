import validator from 'validator';
import { ValidationError } from './types';

// ---- Low-level helpers ----------------------------------------------------

// Centralized malicious pattern detection (single source of truth)
export const MALICIOUS_PATTERNS = [
  /<script/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /data:text\/html/i,
  /vbscript:/i,
  /expression\s*\(/i,
  /eval\s*\(/i,
  /document\./i,
  /window\./i,
  /alert\s*\(/i,
  /prompt\s*\(/i,
  /confirm\s*\(/i,
] as const;

/**
 * Check if a string contains malicious patterns
 * Uses Unicode-aware regex patterns with 'u' flag for better international support
 */
export const containsMalicious = (value: string): boolean => {
  return MALICIOUS_PATTERNS.some(pattern => pattern.test(value));
};

/**
 * Generic list validation helper to eliminate code duplication
 * Validates each item in an array using a provided validation function
 */
export const validateList = <T>(
  items: T[] | undefined,
  validatorFn: (item: T) => ValidationError | null,
  fieldPrefix: string
): ValidationError[] => {
  return (items ?? []).flatMap((item, index) => {
    const error = validatorFn(item);
    return error ? [{ field: `${fieldPrefix}_${index}`, message: error.message }] : [];
  });
};

/**
 * RFC-compliant domain validation using validator.js
 * Supports IDN/punycode and proper TLD requirements
 */
export const isValidDomain = (domain: string): boolean => {
  // Handle wildcard domains separately
  if (domain === '*' || domain.startsWith('*.')) {
    return true;
  }
  
  return validator.isFQDN(domain, { 
    require_tld: true, 
    allow_wildcard: true,
    allow_underscores: false 
  });
};

/**
 * RFC-compliant URL validation using validator.js
 * Supports proper protocols and TLD requirements
 */
export const isValidURL = (url: string): boolean => {
  // Require protocol for URLs
  if (!url.includes('://')) {
    return false;
  }
  
  // Only allow http and https protocols
  const protocol = url.split('://')[0].toLowerCase();
  if (protocol !== 'http' && protocol !== 'https') {
    return false;
  }
  
  return validator.isURL(url, { 
    allow_protocol_relative_urls: false, 
    require_tld: true,
    allow_underscores: true 
  });
};

/**
 * RFC-compliant email validation using validator.js
 */
export const isValidEmail = (email: string): boolean => {
  return validator.isEmail(email);
};

/**
 * RFC 7230 compliant HTTP header name validation
 * Allows all valid token characters: !#$%&'*+.^_`|~ + alphanumeric
 */
export const isValidHeaderName = (name: string): boolean => {
  // RFC 7230 token = 1*tchar
  // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
  const headerNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  return headerNamePattern.test(name);
};

/**
 * RFC 7230 compliant HTTP header value validation
 * Allows visible ASCII + common UTF-8 characters, but rejects malicious patterns
 */
export const isValidHeaderValue = (value: string): boolean => {
  // First check for malicious patterns
  if (containsMalicious(value)) {
    return false;
  }
  
  // Allow visible ASCII + common UTF-8 characters
  // This is more permissive than strict RFC but practical for real-world usage
  const headerValuePattern = /^[\p{L}\p{N}\p{P}\p{S}\s]+$/u;
  return headerValuePattern.test(value);
};