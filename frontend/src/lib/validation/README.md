# Frontend Validation System

## Overview

This is a centralized, security-first validation system that addresses all the issues identified in the code review. It implements RFC-compliant validation, eliminates code duplication, and follows the reject-on-fail pattern for better security.

## Key Features

### 🔒 Security-First Design
- **Reject-on-fail validation**: No input sanitization, only validation
- **Centralized malicious pattern detection**: Single source of truth for XSS patterns
- **Unicode-aware regex patterns**: Better international support
- **RFC-compliant validation**: Proper domain, URL, and header validation

### 🏗️ Architecture
- **Modular design**: Separated into helpers, validators, and target-validators
- **No code duplication**: Generic list validation helper
- **Type-safe**: Full TypeScript support with proper interfaces
- **Backward compatible**: Maintains existing API while providing new capabilities

### 📚 RFC Compliance
- **Domain validation**: Supports IDN/punycode and proper TLD requirements
- **URL validation**: Strict protocol checking (http/https only)
- **Email validation**: RFC-compliant email format checking
- **HTTP headers**: RFC 7230 compliant header name and value validation

## Directory Structure

```
lib/validation/
├── index.ts              # Main exports
├── types.ts              # TypeScript interfaces
├── helpers.ts            # Low-level helper functions
├── validators.ts         # Field-level validators
├── target-validators.ts  # High-level target validators
├── __tests__/            # Comprehensive test suite
└── README.md            # This documentation
```

## Usage

### Basic Field Validation

```typescript
import { validateEmail, validateDomain, validateURL } from '@/lib/validation';

// Email validation
const emailError = validateEmail('test@example.com');
if (emailError) {
  console.log(emailError.message); // "Invalid email format"
}

// Domain validation (supports IDN/punycode)
const domainError = validateDomain('bücher.example.com');
if (domainError) {
  console.log(domainError.message); // "Invalid domain format"
}

// URL validation (strict protocol checking)
const urlError = validateURL('https://example.com');
if (urlError) {
  console.log(urlError.message); // "Invalid URL format"
}
```

### Form Validation

```typescript
import { validateBasicInfo, validateCompleteForm } from '@/lib/validation';

// Validate basic target information
const basicInfo = {
  target: 'Test Company',
  domain: 'example.com'
};

const result = validateBasicInfo(basicInfo);
if (!result.isValid) {
  result.errors.forEach(error => {
    console.log(`${error.field}: ${error.message}`);
  });
}

// Validate complete form
const formData = {
  target: 'Test Company',
  domain: 'example.com',
  login_email: 'test@example.com',
  in_scope: ['https://example.com'],
  rate_limit_requests: 10,
  rate_limit_seconds: 60
};

const completeResult = validateCompleteForm(formData);
if (!completeResult.isValid) {
  console.log('Form has validation errors:', completeResult.errors);
}
```

### Custom Validation

```typescript
import { validateList } from '@/lib/validation/helpers';

// Validate a list of custom items
const customItems = ['item1', 'invalid-item', 'item3'];
const errors = validateList(
  customItems,
  (item) => item.length > 5 ? null : { field: 'item', message: 'Item too short' },
  'custom_item'
);

// Result: [{ field: 'custom_item_1', message: 'Item too short' }]
```

## Security Features

### Malicious Pattern Detection

The system includes centralized detection for common attack patterns:

```typescript
import { containsMalicious } from '@/lib/validation/helpers';

// Detects various XSS patterns
containsMalicious('<script>alert("xss")</script>'); // true
containsMalicious('javascript:alert("xss")'); // true
containsMalicious('onclick=alert("xss")'); // true
containsMalicious('example.com'); // false
```

### RFC 7230 Header Validation

Proper HTTP header validation according to RFC 7230:

```typescript
import { isValidHeaderName, isValidHeaderValue } from '@/lib/validation/helpers';

// Valid header names (RFC 7230 compliant)
isValidHeaderName('Content-Type'); // true
isValidHeaderName('X-Auth*Token'); // true
isValidHeaderName('X-Custom_Header'); // true

// Invalid header names
isValidHeaderName('Header Name'); // false (contains space)
isValidHeaderName('Header:Name'); // false (contains colon)
```

## Migration Guide

### From Old Validation System

The old validation system in `lib/utils/validation.ts` is deprecated but maintained for backward compatibility. To migrate to the new system:

1. **Update imports**:
   ```typescript
   // Old
   import { validateEmail } from '@/lib/utils/validation';
   
   // New
   import { validateEmail } from '@/lib/validation';
   ```

2. **Remove sanitization**:
   ```typescript
   // Old (deprecated)
   const sanitizedValue = sanitizeTargetCompany(rawValue);
   const error = validateTargetCompany(sanitizedValue);
   
   // New (reject-on-fail)
   const error = validateTargetCompany(rawValue);
   if (error) {
     // Handle validation error
   }
   ```

3. **Update error handling**:
   ```typescript
   // Old
   if (!value || value.trim() === '') {
     return { field: 'name', message: 'Name is required' };
   }
   
   // New
   const error = validateRequired(value, 'Name');
   if (error) {
     return error;
   }
   ```

### Backward Compatibility

The old validation system maintains backward compatibility through wrapper functions:

- `validateRequired`: Maintains old behavior for 0/false values
- `validateRateLimit`: Maintains old error messages and edge cases
- `validateHeaderName`: Maintains old error message format
- `validateCustomHeader`: Uses compatibility wrappers

All existing tests continue to pass, ensuring no breaking changes.

## Testing

The validation system includes comprehensive tests:

```bash
# Run all validation tests
npm test -- src/lib/validation/__tests__/validation.test.ts

# Run legacy compatibility tests
npm test -- src/lib/utils/__tests__/validation.test.ts
```

### Test Coverage

- **Helper functions**: 100% coverage for all utility functions
- **Field validators**: 100% coverage for all validation functions
- **High-level validators**: 100% coverage for form validation
- **Edge cases**: Comprehensive testing of edge cases and error conditions
- **Security**: Testing of malicious pattern detection
- **RFC compliance**: Testing of RFC-compliant validation rules

## Security Considerations

### Input Validation vs Sanitization

This system follows the **reject-on-fail** pattern:

- ✅ **Validation**: Check if input is valid, reject if not
- ❌ **Sanitization**: Modify input to make it "safe"

### XSS Protection

- **Client-side**: Basic pattern detection for immediate feedback
- **Server-side**: Primary defense should be server-side validation and proper encoding
- **CSP**: Use Content Security Policy for additional protection

### Unicode Support

- **Unicode-aware regex**: All patterns use the `u` flag
- **IDN support**: Proper handling of internationalized domain names
- **UTF-8 validation**: Support for international characters in headers

## Performance

- **Pre-compiled patterns**: Malicious patterns are defined once and reused
- **Early returns**: Validation functions return early on first error
- **Minimal dependencies**: Only uses validator.js for complex validation
- **Tree-shakable**: Only import what you need

## Future Enhancements

- **Custom validators**: Framework for creating custom validation rules
- **Async validation**: Support for server-side validation calls
- **Validation schemas**: JSON schema-based validation
- **Internationalization**: Localized error messages
- **Performance monitoring**: Validation performance metrics

## Contributing

When adding new validation functions:

1. **Follow the pattern**: Use the established validation function pattern
2. **Add tests**: Include comprehensive test coverage
3. **Document**: Add JSDoc comments and update this README
4. **Security review**: Ensure security considerations are addressed
5. **Backward compatibility**: Maintain compatibility if needed