import { describe, it, expect } from 'vitest';
import {
  validateRequired,
  validateEmail,
  validateDomain,
  validateURL,
  validateCustomHeader,
  validateRateLimit,
  validateBasicInfo,
  validateProgramDetails,
  validateScopeConfig,
  validateAdditionalInfo,
  validateRateLimiting,
  validateCompleteForm,
  getFieldErrors,
  formatValidationErrors,
  validateTargetCompany,
  validateHeaderName,
  validateHeaderValue,
  validateScopeUrl,
  validateTextInfo,
  containsMalicious,
  isValidDomain,
  isValidURL,
  isValidEmail,
  isValidHeaderName,
  isValidHeaderValue,
  validateList
} from '../index';
import { ValidationError } from '../types';

describe('Validation System', () => {
  describe('Helper Functions', () => {
    describe('containsMalicious', () => {
      it('detects script tags', () => {
        expect(containsMalicious('<script>alert("xss")</script>')).toBe(true);
        expect(containsMalicious('<SCRIPT>alert("xss")</SCRIPT>')).toBe(true);
        expect(containsMalicious('<scr<script>ipt>alert("xss")</script>')).toBe(true);
      });

      it('detects javascript protocol', () => {
        expect(containsMalicious('javascript:alert("xss")')).toBe(true);
        expect(containsMalicious('JAVASCRIPT:alert("xss")')).toBe(true);
      });

      it('detects event handlers', () => {
        expect(containsMalicious('onclick=alert("xss")')).toBe(true);
        expect(containsMalicious('onLoad=alert("xss")')).toBe(true);
      });

      it('allows safe content', () => {
        expect(containsMalicious('example.com')).toBe(false);
        expect(containsMalicious('https://example.com')).toBe(false);
        expect(containsMalicious('test@example.com')).toBe(false);
      });
    });

    describe('isValidDomain', () => {
      it('validates basic domains', () => {
        expect(isValidDomain('example.com')).toBe(true);
        expect(isValidDomain('sub.example.com')).toBe(true);
        expect(isValidDomain('example.co.uk')).toBe(true);
      });

      it('supports wildcards', () => {
        expect(isValidDomain('*.example.com')).toBe(true);
        expect(isValidDomain('*')).toBe(true);
      });

      it('rejects invalid domains', () => {
        expect(isValidDomain('example')).toBe(false);
        expect(isValidDomain('example.')).toBe(false);
        expect(isValidDomain('.example.com')).toBe(false);
        expect(isValidDomain('example..com')).toBe(false);
      });

      it('supports IDN/punycode', () => {
        expect(isValidDomain('bücher.example.com')).toBe(true);
        expect(isValidDomain('xn--bcher-kva.example.com')).toBe(true);
      });
    });

    describe('isValidURL', () => {
      it('validates basic URLs', () => {
        expect(isValidURL('https://example.com')).toBe(true);
        expect(isValidURL('http://example.com')).toBe(true);
        expect(isValidURL('https://example.com/path')).toBe(true);
        expect(isValidURL('https://example.com/path?param=value')).toBe(true);
      });

      it('rejects invalid URLs', () => {
        expect(isValidURL('example.com')).toBe(false);
        expect(isValidURL('ftp://example.com')).toBe(false);
        expect(isValidURL('https://example')).toBe(false);
      });
    });

    describe('isValidEmail', () => {
      it('validates basic emails', () => {
        expect(isValidEmail('test@example.com')).toBe(true);
        expect(isValidEmail('user.name@example.co.uk')).toBe(true);
      });

      it('rejects invalid emails', () => {
        expect(isValidEmail('test@')).toBe(false);
        expect(isValidEmail('@example.com')).toBe(false);
        expect(isValidEmail('test.example.com')).toBe(false);
      });
    });

    describe('isValidHeaderName', () => {
      it('validates RFC 7230 compliant header names', () => {
        expect(isValidHeaderName('Content-Type')).toBe(true);
        expect(isValidHeaderName('X-Auth*Token')).toBe(true);
        expect(isValidHeaderName('X-Custom_Header')).toBe(true);
        expect(isValidHeaderName('X-Header~Name')).toBe(true);
      });

      it('rejects invalid header names', () => {
        expect(isValidHeaderName('')).toBe(false);
        expect(isValidHeaderName('Header Name')).toBe(false);
        expect(isValidHeaderName('Header:Name')).toBe(false);
      });
    });

    describe('isValidHeaderValue', () => {
      it('validates header values', () => {
        expect(isValidHeaderValue('application/json')).toBe(true);
        expect(isValidHeaderValue('Bearer token123')).toBe(true);
        expect(isValidHeaderValue('text/html; charset=utf-8')).toBe(true);
      });

      it('rejects malicious header values', () => {
        expect(isValidHeaderValue('<script>alert("xss")</script>')).toBe(false);
        expect(isValidHeaderValue('javascript:alert("xss")')).toBe(false);
      });
    });

    describe('validateList', () => {
      it('validates list of items', () => {
        const items = ['test@example.com', 'invalid-email', 'user@domain.com'];
        const errors = validateList(items, (item) => {
          return isValidEmail(item) ? null : { field: 'email', message: 'Invalid email' };
        }, 'email');
        
        expect(errors).toHaveLength(1);
        expect(errors[0].field).toBe('email_1');
        expect(errors[0].message).toBe('Invalid email');
      });

      it('handles empty arrays', () => {
        const errors = validateList([], () => ({ field: 'test', message: 'error' }), 'test');
        expect(errors).toHaveLength(0);
      });

      it('handles undefined arrays', () => {
        const errors = validateList(undefined, () => ({ field: 'test', message: 'error' }), 'test');
        expect(errors).toHaveLength(0);
      });
    });
  });

  describe('Field-Level Validators', () => {
    describe('validateRequired', () => {
      it('returns error for null/undefined', () => {
        expect(validateRequired(null, 'Field')).toEqual({ field: 'Field', message: 'Field is required' });
        expect(validateRequired(undefined, 'Field')).toEqual({ field: 'Field', message: 'Field is required' });
      });

      it('returns error for empty string', () => {
        expect(validateRequired('', 'Field')).toEqual({ field: 'Field', message: 'Field is required' });
        expect(validateRequired('   ', 'Field')).toEqual({ field: 'Field', message: 'Field is required' });
      });

      it('allows valid values including 0 and false', () => {
        expect(validateRequired(0, 'Field')).toBeNull();
        expect(validateRequired(false, 'Field')).toBeNull();
        expect(validateRequired('valid', 'Field')).toBeNull();
        expect(validateRequired(['item'], 'Field')).toBeNull();
      });
    });

    describe('validateEmail', () => {
      it('validates valid emails', () => {
        expect(validateEmail('test@example.com')).toBeNull();
        expect(validateEmail('user.name@example.co.uk')).toBeNull();
      });

      it('rejects invalid emails', () => {
        expect(validateEmail('test@')).toEqual({ field: 'email', message: 'Invalid email format' });
        expect(validateEmail('@example.com')).toEqual({ field: 'email', message: 'Invalid email format' });
      });

      it('rejects malicious emails', () => {
        expect(validateEmail('<script>alert("xss")</script>')).toEqual({ field: 'email', message: 'Email contains malicious patterns' });
        expect(validateEmail('javascript:alert("xss")')).toEqual({ field: 'email', message: 'Email contains malicious patterns' });
      });

      it('allows empty emails (optional)', () => {
        expect(validateEmail('')).toBeNull();
        expect(validateEmail('   ')).toBeNull();
      });
    });

    describe('validateDomain', () => {
      it('validates valid domains', () => {
        expect(validateDomain('example.com')).toBeNull();
        expect(validateDomain('sub.example.com')).toBeNull();
        expect(validateDomain('*.example.com')).toBeNull();
      });

      it('rejects invalid domains', () => {
        expect(validateDomain('example')).toEqual({ field: 'domain', message: 'Invalid domain format' });
        expect(validateDomain('example.')).toEqual({ field: 'domain', message: 'Invalid domain format' });
      });

      it('rejects malicious domains', () => {
        expect(validateDomain('<script>alert("xss")</script>')).toEqual({ field: 'domain', message: 'Domain contains malicious patterns' });
      });

      it('allows empty domains (optional)', () => {
        expect(validateDomain('')).toBeNull();
        expect(validateDomain('   ')).toBeNull();
      });
    });

    describe('validateRateLimit', () => {
      it('allows valid rate limits', () => {
        expect(validateRateLimit(10, 60)).toBeNull();
        expect(validateRateLimit(1, 1)).toBeNull();
      });

      it('rejects invalid rate limits', () => {
        expect(validateRateLimit(0, 60)).toEqual({ field: 'rate_limit_requests', message: 'Requests must be greater than 0' });
        expect(validateRateLimit(10, 0)).toEqual({ field: 'rate_limit_seconds', message: 'Seconds must be greater than 0' });
        expect(validateRateLimit(-1, 60)).toEqual({ field: 'rate_limit_requests', message: 'Requests must be greater than 0' });
      });

      it('allows undefined (not set)', () => {
        expect(validateRateLimit(undefined, undefined)).toBeNull();
        expect(validateRateLimit(10, undefined)).toBeNull();
        expect(validateRateLimit(undefined, 60)).toBeNull();
      });
    });

    describe('validateHeaderName', () => {
      it('validates RFC 7230 compliant header names', () => {
        expect(validateHeaderName('Content-Type')).toBeNull();
        expect(validateHeaderName('X-Auth*Token')).toBeNull();
        expect(validateHeaderName('X-Custom_Header')).toBeNull();
      });

      it('rejects invalid header names', () => {
        expect(validateHeaderName('')).toEqual({ field: 'header_name', message: 'Header name is required' });
        expect(validateHeaderName('Header Name')).toEqual({ field: 'header_name', message: 'Header name contains invalid characters' });
      });

      it('rejects malicious header names', () => {
        expect(validateHeaderName('<script>alert("xss")</script>')).toEqual({ field: 'header_name', message: 'Header name contains malicious patterns' });
      });
    });

    describe('validateHeaderValue', () => {
      it('validates header values', () => {
        expect(validateHeaderValue('application/json')).toBeNull();
        expect(validateHeaderValue('Bearer token123')).toBeNull();
      });

      it('rejects empty header values', () => {
        expect(validateHeaderValue('')).toEqual({ field: 'header_value', message: 'Header value is required' });
      });

      it('rejects malicious header values', () => {
        expect(validateHeaderValue('<script>alert("xss")</script>')).toEqual({ field: 'header_value', message: 'Header value contains malicious patterns' });
      });
    });
  });

  describe('High-Level Validators', () => {
    describe('validateBasicInfo', () => {
      it('validates complete basic info', () => {
        const result = validateBasicInfo({
          target: 'Test Company',
          domain: 'example.com'
        });
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('handles legacy field names', () => {
        const result = validateBasicInfo({
          name: 'Test Company',
          value: 'example.com'
        });
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns errors for invalid data', () => {
        const result = validateBasicInfo({
          target: '',
          domain: 'invalid domain'
        });
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(2);
      });
    });

    describe('validateProgramDetails', () => {
      it('validates valid emails', () => {
        const result = validateProgramDetails({
          login_email: 'test@example.com',
          researcher_email: 'researcher@example.com'
        });
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns errors for invalid emails', () => {
        const result = validateProgramDetails({
          login_email: 'invalid-email',
          researcher_email: 'also-invalid'
        });
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(2);
      });
    });

    describe('validateScopeConfig', () => {
      it('validates valid scope URLs', () => {
        const result = validateScopeConfig({
          in_scope: ['https://example.com', '*.example.com'],
          out_of_scope: ['https://api.example.com']
        });
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns errors for invalid URLs', () => {
        const result = validateScopeConfig({
          in_scope: ['invalid-url'],
          out_of_scope: ['also-invalid']
        });
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(2);
      });
    });

    describe('validateCompleteForm', () => {
      it('validates complete valid form', () => {
        const formData = {
          target: 'Test Company',
          domain: 'example.com',
          login_email: 'test@example.com',
          researcher_email: 'researcher@example.com',
          in_scope: ['https://example.com'],
          out_of_scope: ['https://api.example.com'],
          rate_limit_requests: 10,
          rate_limit_seconds: 60,
          custom_headers: [{ name: 'X-Custom', value: 'value' }],
          additional_info: ['Additional info'],
          notes: ['Note']
        };
        
        const result = validateCompleteForm(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns all errors for invalid form', () => {
        const formData = {
          target: '',
          domain: 'invalid domain',
          login_email: 'invalid-email',
          in_scope: ['invalid-url']
        };
        
        const result = validateCompleteForm(formData);
        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Helper Functions', () => {
    describe('getFieldErrors', () => {
      it('returns errors for specific field', () => {
        const errors: ValidationError[] = [
          { field: 'email', message: 'Invalid email' },
          { field: 'name', message: 'Name required' },
          { field: 'email', message: 'Email too long' }
        ];
        
        const emailErrors = getFieldErrors(errors, 'email');
        expect(emailErrors).toEqual(['Invalid email', 'Email too long']);
      });
    });

    describe('formatValidationErrors', () => {
      it('formats errors for display', () => {
        const errors: ValidationError[] = [
          { field: 'email', message: 'Invalid email' },
          { field: 'name', message: 'Name required' }
        ];
        
        const formatted = formatValidationErrors(errors);
        expect(formatted).toEqual(['email: Invalid email', 'name: Name required']);
      });
    });
  });
});