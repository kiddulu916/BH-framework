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
  validateAdditionalRules,
  validateRateLimiting,
  validateCompleteForm,
  getFieldErrors,
  formatValidationErrors,
} from '../validation';
import { BugBountyPlatform } from '@/types/target';

describe('Validation Utilities', () => {
  describe('Basic Validation Functions', () => {
    describe('validateRequired', () => {
      it('returns error for empty string', () => {
        const result = validateRequired('', 'Field Name');
        expect(result).toEqual({ field: 'Field Name', message: 'Field Name is required' });
      });

      it('returns error for whitespace only', () => {
        const result = validateRequired('   ', 'Field Name');
        expect(result).toEqual({ field: 'Field Name', message: 'Field Name is required' });
      });

      it('returns null for valid value', () => {
        const result = validateRequired('valid value', 'Field Name');
        expect(result).toBeNull();
      });

      it('returns null for non-empty array', () => {
        const result = validateRequired(['item1', 'item2'], 'Field Name');
        expect(result).toBeNull();
      });

      it('returns null for empty array (not considered required)', () => {
        const result = validateRequired([], 'Field Name');
        expect(result).toBeNull();
      });

      it('returns null for non-empty object', () => {
        const result = validateRequired({ key: 'value' }, 'Field Name');
        expect(result).toBeNull();
      });

      it('returns error for zero number (considered falsy)', () => {
        const result = validateRequired(0, 'Field Name');
        expect(result).toEqual({ field: 'Field Name', message: 'Field Name is required' });
      });

      it('returns error for false boolean (considered falsy)', () => {
        const result = validateRequired(false, 'Field Name');
        expect(result).toEqual({ field: 'Field Name', message: 'Field Name is required' });
      });
    });

    describe('validateEmail', () => {
      it('returns null for valid email', () => {
        const result = validateEmail('test@example.com');
        expect(result).toBeNull();
      });

      it('returns null for empty email (optional)', () => {
        const result = validateEmail('');
        expect(result).toBeNull();
      });

      it('returns error for invalid email format', () => {
        const result = validateEmail('invalid-email');
        expect(result).toEqual({ field: 'email', message: 'Invalid email format' });
      });

      it('returns error for email without domain', () => {
        const result = validateEmail('test@');
        expect(result).toEqual({ field: 'email', message: 'Invalid email format' });
      });
    });

    describe('validateDomain', () => {
      it('returns null for valid domain', () => {
        const result = validateDomain('example.com');
        expect(result).toBeNull();
      });

      it('returns null for empty domain (optional)', () => {
        const result = validateDomain('');
        expect(result).toBeNull();
      });

      it('returns error for invalid domain format', () => {
        const result = validateDomain('invalid domain');
        expect(result).toEqual({ field: 'domain', message: 'Invalid domain format' });
      });

      it('returns error for domain starting with hyphen', () => {
        const result = validateDomain('-example.com');
        expect(result).toEqual({ field: 'domain', message: 'Invalid domain format' });
      });

      it('returns error for domain ending with hyphen', () => {
        const result = validateDomain('example-.com');
        expect(result).toEqual({ field: 'domain', message: 'Invalid domain format' });
      });
    });

    describe('validateURL', () => {
      it('returns null for valid URL', () => {
        const result = validateURL('https://example.com');
        expect(result).toBeNull();
      });

      it('returns null for empty URL (optional)', () => {
        const result = validateURL('');
        expect(result).toBeNull();
      });

      it('returns error for invalid URL format', () => {
        const result = validateURL('not-a-url');
        expect(result).toEqual({ field: 'url', message: 'Invalid URL format' });
      });

      it('returns error for URL without protocol', () => {
        const result = validateURL('example.com');
        expect(result).toEqual({ field: 'url', message: 'Invalid URL format' });
      });
    });

    describe('validateCustomHeader', () => {
      it('returns null for valid header', () => {
        const result = validateCustomHeader({ name: 'Authorization', value: 'Bearer token' });
        expect(result).toBeNull();
      });

      it('returns error for empty header name', () => {
        const result = validateCustomHeader({ name: '', value: 'Bearer token' });
        expect(result).toEqual({ field: 'header_name', message: 'Header name is required' });
      });

      it('returns error for empty header value', () => {
        const result = validateCustomHeader({ name: 'Authorization', value: '' });
        expect(result).toEqual({ field: 'header_value', message: 'Header value is required' });
      });

      it('returns error for invalid header name format', () => {
        const result = validateCustomHeader({ name: 'Invalid Header', value: 'Bearer token' });
        expect(result).toEqual({ 
          field: 'header_name', 
          message: 'Header name can only contain letters, numbers, hyphens, and underscores' 
        });
      });
    });

    describe('validateRateLimit', () => {
      it('returns null for valid rate limit', () => {
        const result = validateRateLimit(10, 60);
        expect(result).toBeNull();
      });

      it('returns error for zero requests', () => {
        const result = validateRateLimit(0, 60);
        expect(result).toEqual({ field: 'rate_limit_requests', message: 'Rate limit requests must be greater than 0' });
      });

      it('returns error for negative requests', () => {
        const result = validateRateLimit(-1, 60);
        expect(result).toEqual({ field: 'rate_limit_requests', message: 'Rate limit requests must be greater than 0' });
      });

      it('returns error for zero seconds', () => {
        const result = validateRateLimit(10, 0);
        expect(result).toEqual({ field: 'rate_limit_seconds', message: 'Rate limit time must be greater than 0' });
      });

      it('returns error for negative seconds', () => {
        const result = validateRateLimit(10, -1);
        expect(result).toEqual({ field: 'rate_limit_seconds', message: 'Rate limit time must be greater than 0' });
      });

      it('returns null when both values are falsy', () => {
        const result = validateRateLimit(0, 0);
        expect(result).toBeNull();
      });
    });
  });

  describe('Step-Specific Validation Functions', () => {
    describe('validateBasicInfo', () => {
      it('returns valid for complete data', () => {
        const formData = {
          target: 'Test Company',
          domain: 'example.com',
        };
        const result = validateBasicInfo(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns errors for missing target', () => {
        const formData = {
          target: '',
          domain: 'example.com',
        };
        const result = validateBasicInfo(formData);
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].field).toBe('Target Company');
      });

      it('returns errors for invalid domain', () => {
        const formData = {
          target: 'Test Company',
          domain: 'invalid domain',
        };
        const result = validateBasicInfo(formData);
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].field).toBe('domain');
      });

      it('handles legacy field names', () => {
        const formData = {
          name: 'Test Company',
          value: 'example.com',
        };
        const result = validateBasicInfo(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('validateProgramDetails', () => {
      it('returns valid for complete data', () => {
        const formData = {
          platform: BugBountyPlatform.HACKERONE,
          platform_email: 'test@example.com',
          researcher_email: 'researcher@example.com',
        };
        const result = validateProgramDetails(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns error for invalid email', () => {
        const formData = {
          platform: BugBountyPlatform.HACKERONE,
          platform_email: 'invalid-email',
          researcher_email: 'researcher@example.com',
        };
        const result = validateProgramDetails(formData);
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].field).toBe('email');
      });

      it('handles optional fields', () => {
        const formData = {
          platform: BugBountyPlatform.HACKERONE,
          platform_email: '',
          researcher_email: '',
        };
        const result = validateProgramDetails(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('validateScopeConfig', () => {
      it('returns valid for valid URLs', () => {
        const formData = {
          in_scope: ['https://example.com'],
          out_of_scope: ['https://excluded.example.com'],
        };
        const result = validateScopeConfig(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns error for invalid URL in in_scope', () => {
        const formData = {
          in_scope: ['not-a-url'],
          out_of_scope: ['https://excluded.example.com'],
        };
        const result = validateScopeConfig(formData);
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].field).toBe('in_scope_0');
      });

      it('handles empty arrays', () => {
        const formData = {
          in_scope: [],
          out_of_scope: [],
        };
        const result = validateScopeConfig(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('validateAdditionalRules', () => {
      it('returns valid for valid custom headers', () => {
        const formData = {
          custom_headers: [
            { name: 'Authorization', value: 'Bearer token' },
            { name: 'User-Agent', value: 'Custom Agent' },
          ],
        };
        const result = validateAdditionalRules(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns error for invalid custom header', () => {
        const formData = {
          custom_headers: [
            { name: 'Invalid Header', value: 'Bearer token' },
          ],
        };
        const result = validateAdditionalRules(formData);
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].field).toBe('custom_header_0');
      });

      it('handles empty custom headers', () => {
        const formData = {
          custom_headers: [],
        };
        const result = validateAdditionalRules(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('validateRateLimiting', () => {
      it('returns valid for valid rate limits', () => {
        const formData = {
          rate_limit_requests: 10,
          rate_limit_seconds: 60,
        };
        const result = validateRateLimiting(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns error for invalid rate limit', () => {
        const formData = {
          rate_limit_requests: 0,
          rate_limit_seconds: 60,
        };
        const result = validateRateLimiting(formData);
        expect(result.isValid).toBe(false);
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].field).toBe('rate_limit_requests');
      });

      it('handles missing rate limits', () => {
        const formData = {};
        const result = validateRateLimiting(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });
  });

  describe('Complete Form Validation', () => {
    describe('validateCompleteForm', () => {
      it('returns valid for complete form data', () => {
        const formData = {
          target: 'Test Company',
          domain: 'example.com',
          is_primary: true,
          platform: BugBountyPlatform.HACKERONE,
          platform_email: 'test@example.com',
          researcher_email: 'researcher@example.com',
          in_scope: ['https://example.com'],
          out_of_scope: ['https://excluded.example.com'],
          additional_info: ['Follow responsible disclosure'],
          notes: ['No DDoS attacks'],
          rate_limit_requests: 10,
          rate_limit_seconds: 60,
          custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
        };
        const result = validateCompleteForm(formData);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('returns errors for incomplete form data', () => {
        const formData = {
          target: '',
          domain: '',
          is_primary: false,
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
        const errors = [
          { field: 'target', message: 'Target is required' },
          { field: 'domain', message: 'Domain is invalid' },
          { field: 'target', message: 'Target must be unique' },
        ];
        const targetErrors = getFieldErrors(errors, 'target');
        expect(targetErrors).toHaveLength(2);
        expect(targetErrors[0]).toBe('Target is required');
        expect(targetErrors[1]).toBe('Target must be unique');
      });

      it('returns empty array for field with no errors', () => {
        const errors = [
          { field: 'target', message: 'Target is required' },
        ];
        const domainErrors = getFieldErrors(errors, 'domain');
        expect(domainErrors).toHaveLength(0);
      });
    });

    describe('formatValidationErrors', () => {
      it('formats errors as string array', () => {
        const errors = [
          { field: 'target', message: 'Target is required' },
          { field: 'domain', message: 'Domain is invalid' },
        ];
        const formatted = formatValidationErrors(errors);
        expect(formatted).toEqual([
          'target: Target is required',
          'domain: Domain is invalid',
        ]);
      });

      it('returns empty array for no errors', () => {
        const formatted = formatValidationErrors([]);
        expect(formatted).toEqual([]);
      });
    });
  });
}); 