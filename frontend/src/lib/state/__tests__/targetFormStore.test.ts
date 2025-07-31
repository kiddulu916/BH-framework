import { describe, it, expect, beforeEach } from 'vitest';
import { useTargetFormStore } from '../targetFormStore';
import { BugBountyPlatform } from '@/types/target';

describe('TargetFormStore', () => {
  beforeEach(() => {
    // Reset the store before each test
    useTargetFormStore.getState().resetForm();
  });

  describe('Initial State', () => {
    it('has correct initial form data', () => {
      const { formData } = useTargetFormStore.getState();
      
      expect(formData.target).toBe('');
      expect(formData.domain).toBe('');
      expect(formData.is_primary).toBe(false);
      expect(formData.platform).toBe(BugBountyPlatform.HACKERONE);
      expect(formData.login_email).toBe('');
      expect(formData.researcher_email).toBe('');
      expect(formData.in_scope).toEqual([]);
      expect(formData.out_of_scope).toEqual([]);
      expect(formData.additional_info).toEqual([]);
      expect(formData.notes).toEqual([]);
      expect(formData.rate_limit_requests).toBe(0);
      expect(formData.rate_limit_seconds).toBe(0);
      expect(formData.custom_headers).toEqual([]);
    });

    it('has correct initial state values', () => {
      const state = useTargetFormStore.getState();
      
      expect(state.currentStep).toBe(1);
      expect(state.validationErrors).toEqual([]);
      expect(state.isSubmitting).toBe(false);
      expect(state.submitError).toBeNull();
    });
  });

  describe('Navigation Actions', () => {
    it('increments current step when nextStep is called', () => {
      const { nextStep, currentStep } = useTargetFormStore.getState();
      
      expect(currentStep).toBe(1);
      nextStep();
      expect(useTargetFormStore.getState().currentStep).toBe(2);
    });

    it('decrements current step when prevStep is called', () => {
      const { nextStep, prevStep } = useTargetFormStore.getState();
      
      // Move to step 2 first
      nextStep();
      expect(useTargetFormStore.getState().currentStep).toBe(2);
      
      // Then go back
      prevStep();
      expect(useTargetFormStore.getState().currentStep).toBe(1);
    });

    it('does not go below step 1', () => {
      const { prevStep } = useTargetFormStore.getState();
      
      prevStep();
      expect(useTargetFormStore.getState().currentStep).toBe(1);
    });

    it('does not go above step 6', () => {
      const { nextStep } = useTargetFormStore.getState();
      
      // Move to step 6
      for (let i = 0; i < 6; i++) {
        nextStep();
      }
      expect(useTargetFormStore.getState().currentStep).toBe(6);
      
      // Try to go beyond step 6
      nextStep();
      expect(useTargetFormStore.getState().currentStep).toBe(6);
    });
  });

  describe('Form Data Updates', () => {
    it('updates form data correctly', () => {
      const { updateFormData } = useTargetFormStore.getState();
      
      updateFormData({
        target: 'Test Company',
        domain: 'example.com',
        is_primary: true,
      });
      
      const { formData } = useTargetFormStore.getState();
      expect(formData.target).toBe('Test Company');
      expect(formData.domain).toBe('example.com');
      expect(formData.is_primary).toBe(true);
    });

    it('merges partial updates correctly', () => {
      const { updateFormData } = useTargetFormStore.getState();
      
      // Update target first
      updateFormData({ target: 'Test Company' });
      expect(useTargetFormStore.getState().formData.target).toBe('Test Company');
      
      // Update domain without affecting target
      updateFormData({ domain: 'example.com' });
      const { formData } = useTargetFormStore.getState();
      expect(formData.target).toBe('Test Company');
      expect(formData.domain).toBe('example.com');
    });

    it('clears validation errors when form data is updated', () => {
      const { setValidationErrors, updateFormData } = useTargetFormStore.getState();
      
      // Set some validation errors
      setValidationErrors([
        { field: 'target', message: 'Target is required' },
      ]);
      expect(useTargetFormStore.getState().validationErrors).toHaveLength(1);
      
      // Update form data
      updateFormData({ target: 'Test Company' });
      expect(useTargetFormStore.getState().validationErrors).toHaveLength(0);
    });

    it('clears submit error when form data is updated', () => {
      const { setSubmitError, updateFormData } = useTargetFormStore.getState();
      
      // Set submit error
      setSubmitError('API Error');
      expect(useTargetFormStore.getState().submitError).toBe('API Error');
      
      // Update form data
      updateFormData({ target: 'Test Company' });
      expect(useTargetFormStore.getState().submitError).toBeNull();
    });
  });

  describe('Validation Error Management', () => {
    it('sets validation errors correctly', () => {
      const { setValidationErrors } = useTargetFormStore.getState();
      
      const errors = [
        { field: 'target', message: 'Target is required' },
        { field: 'domain', message: 'Domain is invalid' },
      ];
      
      setValidationErrors(errors);
      expect(useTargetFormStore.getState().validationErrors).toEqual(errors);
    });

    it('clears validation errors correctly', () => {
      const { setValidationErrors, clearValidationErrors } = useTargetFormStore.getState();
      
      // Set errors first
      setValidationErrors([
        { field: 'target', message: 'Target is required' },
      ]);
      expect(useTargetFormStore.getState().validationErrors).toHaveLength(1);
      
      // Clear errors
      clearValidationErrors();
      expect(useTargetFormStore.getState().validationErrors).toHaveLength(0);
    });
  });

  describe('Submission State Management', () => {
    it('sets submitting state correctly', () => {
      const { setSubmitting } = useTargetFormStore.getState();
      
      setSubmitting(true);
      expect(useTargetFormStore.getState().isSubmitting).toBe(true);
      
      setSubmitting(false);
      expect(useTargetFormStore.getState().isSubmitting).toBe(false);
    });

    it('sets submit error correctly', () => {
      const { setSubmitError } = useTargetFormStore.getState();
      
      setSubmitError('API Error');
      expect(useTargetFormStore.getState().submitError).toBe('API Error');
      
      setSubmitError(null);
      expect(useTargetFormStore.getState().submitError).toBeNull();
    });
  });

  describe('Form Reset', () => {
    it('resets form data to initial state', () => {
      const { updateFormData, resetForm } = useTargetFormStore.getState();
      
      // Update form data
      updateFormData({
        target: 'Test Company',
        domain: 'example.com',
        is_primary: true,
        platform: BugBountyPlatform.BUGCROWD,
      });
      
      // Reset form
      resetForm();
      
      const { formData } = useTargetFormStore.getState();
      expect(formData.target).toBe('');
      expect(formData.domain).toBe('');
      expect(formData.is_primary).toBe(false);
      expect(formData.platform).toBe(BugBountyPlatform.HACKERONE);
    });

    it('resets state values to initial state', () => {
      const { nextStep, setValidationErrors, setSubmitting, setSubmitError, resetForm } = useTargetFormStore.getState();
      
      // Modify state
      nextStep();
      setValidationErrors([{ field: 'target', message: 'Error' }]);
      setSubmitting(true);
      setSubmitError('API Error');
      
      // Reset
      resetForm();
      
      const state = useTargetFormStore.getState();
      expect(state.currentStep).toBe(1);
      expect(state.validationErrors).toEqual([]);
      expect(state.isSubmitting).toBe(false);
      expect(state.submitError).toBeNull();
    });
  });

  describe('Complex Form Data Updates', () => {
    it('handles array updates correctly', () => {
      const { updateFormData } = useTargetFormStore.getState();
      
      updateFormData({
        in_scope: ['https://example.com', 'https://api.example.com'],
        out_of_scope: ['https://admin.example.com'],
      });
      
      const { formData } = useTargetFormStore.getState();
      expect(formData.in_scope).toEqual(['https://example.com', 'https://api.example.com']);
      expect(formData.out_of_scope).toEqual(['https://admin.example.com']);
    });

    it('handles custom headers updates correctly', () => {
      const { updateFormData } = useTargetFormStore.getState();
      
      const customHeaders = [
        { name: 'Authorization', value: 'Bearer token' },
        { name: 'User-Agent', value: 'Custom Agent' },
      ];
      
      updateFormData({ custom_headers: customHeaders });
      
      const { formData } = useTargetFormStore.getState();
      expect(formData.custom_headers).toEqual(customHeaders);
    });

    it('handles rate limiting updates correctly', () => {
      const { updateFormData } = useTargetFormStore.getState();
      
      updateFormData({
        rate_limit_requests: 10,
        rate_limit_seconds: 60,
      });
      
      const { formData } = useTargetFormStore.getState();
      expect(formData.rate_limit_requests).toBe(10);
      expect(formData.rate_limit_seconds).toBe(60);
    });
  });

  describe('Legacy Field Compatibility', () => {
    it('handles legacy field names correctly', () => {
      const { updateFormData } = useTargetFormStore.getState();
      
      // Test legacy field mapping
      updateFormData({
        target: 'Test Company', // Legacy field
        domain: 'example.com', // Legacy field
        login_email: 'test@example.com', // Use login_email instead
        researcher_email: 'researcher@example.com', // Legacy field
      });
      
      const { formData } = useTargetFormStore.getState();
      expect(formData.target).toBe('Test Company');
      expect(formData.domain).toBe('example.com');
      expect(formData.login_email).toBe('test@example.com');
      expect(formData.researcher_email).toBe('researcher@example.com');
    });

    it('handles both legacy and new field names', () => {
      const { updateFormData } = useTargetFormStore.getState();
      
      updateFormData({
        target: 'Test Company', // Legacy
        name: 'New Company Name', // New
        domain: 'example.com', // Legacy
        value: 'new-example.com', // New
      });
      
      const { formData } = useTargetFormStore.getState();
      expect(formData.target).toBe('Test Company');
      expect(formData.name).toBe('New Company Name');
      expect(formData.domain).toBe('example.com');
      expect(formData.value).toBe('new-example.com');
    });
  });
}); 