import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import { createTarget } from '@/lib/api/targets';
import TargetProfileBuilder from '../TargetProfileBuilder';

// Mock dependencies
vi.mock('@/lib/state/targetFormStore');
vi.mock('@/lib/api/targets');
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <div>{children}</div>,
}));

// Mock window.alert
global.alert = vi.fn();

const mockUseTargetFormStore = vi.mocked(useTargetFormStore);
const mockCreateTarget = vi.mocked(createTarget);

describe('TargetProfileBuilder Integration Tests', () => {
  const mockUpdateFormData = vi.fn();
  const mockNextStep = vi.fn();
  const mockPrevStep = vi.fn();
  const mockResetForm = vi.fn();
  const mockSetValidationErrors = vi.fn();
  const mockClearValidationErrors = vi.fn();
  const mockSetSubmitting = vi.fn();
  const mockSetSubmitError = vi.fn();

  beforeEach(() => {
    // Clear all mocks before each test
    vi.clearAllMocks();
    
    mockUseTargetFormStore.mockReturnValue({
      formData: {
        target: '',
        domain: '',
        is_primary: false,
        platform: 'HACKERONE',
        platform_email: '',
        researcher_email: '',
        in_scope: [],
        out_of_scope: [],
        additional_info: [],
        notes: [],
        rate_limit_requests: 0,
        rate_limit_seconds: 0,
        custom_headers: [],
      },
      updateFormData: mockUpdateFormData,
      currentStep: 1,
      nextStep: mockNextStep,
      prevStep: mockPrevStep,
      resetForm: mockResetForm,
      validationErrors: [],
      isSubmitting: false,
      submitError: null,
      setValidationErrors: mockSetValidationErrors,
      clearValidationErrors: mockClearValidationErrors,
      setSubmitting: mockSetSubmitting,
      setSubmitError: mockSetSubmitError,
    });

    mockCreateTarget.mockResolvedValue({
      success: true,
      message: 'Target created successfully',
      data: { id: '123', name: 'Test Company' },
    });
  });

  it('renders the form wizard with step indicator', () => {
    render(<TargetProfileBuilder />);
    
    expect(screen.getByText(/build target profile/i)).toBeInTheDocument();
    expect(screen.getByText(/step 1 of 6/i)).toBeInTheDocument();
  });

  it('navigates between steps correctly', async () => {
    render(<TargetProfileBuilder />);
    
    // Fill step 1 data
    const targetInput = screen.getByLabelText(/target company/i);
    const domainInput = screen.getByLabelText(/domain\/ip address/i);
    
    fireEvent.change(targetInput, { target: { value: 'Test Company' } });
    fireEvent.change(domainInput, { target: { value: 'example.com' } });
    
    // Click Next
    const nextButton = screen.getByText(/next/i);
    fireEvent.click(nextButton);
    
    await waitFor(() => {
      expect(mockNextStep).toHaveBeenCalled();
    });
  });

  it('saves step data when save button is clicked', async () => {
    render(<TargetProfileBuilder />);
    
    // Fill step 1 data
    const targetInput = screen.getByLabelText(/target company/i);
    const domainInput = screen.getByLabelText(/domain\/ip address/i);
    
    fireEvent.change(targetInput, { target: { value: 'Test Company' } });
    fireEvent.change(domainInput, { target: { value: 'example.com' } });
    
    // Click Save Step Data
    const saveButton = screen.getByText(/save to target's profile/i);
    fireEvent.click(saveButton);
    
    await waitFor(() => {
      expect(mockUpdateFormData).toHaveBeenCalledWith({
        target: 'Test Company',
        domain: 'example.com',
        is_primary: false,
      });
    });
  });

  it('submits the complete form successfully', async () => {
    // Mock complete form data
    mockUseTargetFormStore.mockReturnValue({
      formData: {
        target: 'Test Company',
        domain: 'example.com',
        is_primary: true,
        platform: 'HACKERONE',
        platform_email: 'test@example.com',
        researcher_email: 'researcher@example.com',
        in_scope: ['https://example.com'],
        out_of_scope: ['https://excluded.example.com'],
        additional_info: ['Follow responsible disclosure'],
        notes: ['No DDoS attacks'],
        rate_limit_requests: 10,
        rate_limit_seconds: 60,
        custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
      },
      updateFormData: mockUpdateFormData,
      currentStep: 6, // Review step
      nextStep: mockNextStep,
      prevStep: mockPrevStep,
      resetForm: mockResetForm,
      validationErrors: [],
      isSubmitting: false,
      submitError: null,
      setValidationErrors: mockSetValidationErrors,
      clearValidationErrors: mockClearValidationErrors,
      setSubmitting: mockSetSubmitting,
      setSubmitError: mockSetSubmitError,
    });

    render(<TargetProfileBuilder />);
    
    // Click Submit
    const submitButton = screen.getByText(/create target profile/i);
    fireEvent.click(submitButton);
    
    await waitFor(() => {
      expect(mockSetSubmitting).toHaveBeenCalledWith(true);
      expect(mockCreateTarget).toHaveBeenCalled();
    });
  });

  it('handles form submission errors', async () => {
    mockCreateTarget.mockRejectedValue(new Error('API Error'));
    
    // Mock complete form data
    mockUseTargetFormStore.mockReturnValue({
      formData: {
        target: 'Test Company',
        domain: 'example.com',
        is_primary: true,
        platform: 'HACKERONE',
        platform_email: 'test@example.com',
        researcher_email: 'researcher@example.com',
        in_scope: ['https://example.com'],
        out_of_scope: ['https://excluded.example.com'],
        additional_info: ['Follow responsible disclosure'],
        notes: ['No DDoS attacks'],
        rate_limit_requests: 10,
        rate_limit_seconds: 60,
        custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
      },
      updateFormData: mockUpdateFormData,
      currentStep: 6,
      nextStep: mockNextStep,
      prevStep: mockPrevStep,
      resetForm: mockResetForm,
      validationErrors: [],
      isSubmitting: false,
      submitError: null,
      setValidationErrors: mockSetValidationErrors,
      clearValidationErrors: mockClearValidationErrors,
      setSubmitting: mockSetSubmitting,
      setSubmitError: mockSetSubmitError,
    });

    render(<TargetProfileBuilder />);
    
    // Click Submit
    const submitButton = screen.getByText(/create target profile/i);
    fireEvent.click(submitButton);
    
    await waitFor(() => {
      expect(mockSetSubmitError).toHaveBeenCalledWith('API Error');
      expect(mockSetSubmitting).toHaveBeenCalledWith(false);
    });
  });

  it('validates form data before submission', async () => {
    // Mock incomplete form data with validation errors
    mockUseTargetFormStore.mockReturnValue({
      formData: {
        target: '',
        domain: '',
        is_primary: false,
        platform: 'HACKERONE',
        platform_email: '',
        researcher_email: '',
        in_scope: [],
        out_of_scope: [],
        additional_info: [],
        notes: [],
        rate_limit_requests: 0,
        rate_limit_seconds: 0,
        custom_headers: [],
      },
      updateFormData: mockUpdateFormData,
      currentStep: 6,
      nextStep: mockNextStep,
      prevStep: mockPrevStep,
      resetForm: mockResetForm,
      validationErrors: [
        { field: 'target', message: 'Target Company is required' },
        { field: 'domain', message: 'Domain is required' },
      ],
      isSubmitting: false,
      submitError: null,
      setValidationErrors: mockSetValidationErrors,
      clearValidationErrors: mockClearValidationErrors,
      setSubmitting: mockSetSubmitting,
      setSubmitError: mockSetSubmitError,
    });

    render(<TargetProfileBuilder />);
    
    // Check that the submit button is disabled due to validation errors
    const submitButton = screen.getByText('Create Target Profile');
    expect(submitButton).toBeDisabled();
    
    // Try to click the disabled button (should not trigger submission)
    fireEvent.click(submitButton);
    
    // Wait a bit to ensure no async operations occur
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Verify that createTarget was not called
    expect(mockCreateTarget).not.toHaveBeenCalled();
  });

  it('shows loading state during submission', async () => {
    mockUseTargetFormStore.mockReturnValue({
      formData: {
        target: 'Test Company',
        domain: 'example.com',
        is_primary: true,
        platform: 'HACKERONE',
        platform_email: 'test@example.com',
        researcher_email: 'researcher@example.com',
        in_scope: ['https://example.com'],
        out_of_scope: ['https://excluded.example.com'],
        additional_info: ['Follow responsible disclosure'],
        notes: ['No DDoS attacks'],
        rate_limit_requests: 10,
        rate_limit_seconds: 60,
        custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
      },
      updateFormData: mockUpdateFormData,
      currentStep: 6,
      nextStep: mockNextStep,
      prevStep: mockPrevStep,
      resetForm: mockResetForm,
      validationErrors: [],
      isSubmitting: true,
      submitError: null,
      setValidationErrors: mockSetValidationErrors,
      clearValidationErrors: mockClearValidationErrors,
      setSubmitting: mockSetSubmitting,
      setSubmitError: mockSetSubmitError,
    });

    render(<TargetProfileBuilder />);
    
    const submitButton = screen.getByText('Create Target Profile');
    expect(submitButton).toBeDisabled();
  });

  it('displays submit error when present', () => {
    mockUseTargetFormStore.mockReturnValue({
      formData: {
        target: 'Test Company',
        domain: 'example.com',
        is_primary: true,
        platform: 'HACKERONE',
        platform_email: 'test@example.com',
        researcher_email: 'researcher@example.com',
        in_scope: ['https://example.com'],
        out_of_scope: ['https://excluded.example.com'],
        additional_info: ['Follow responsible disclosure'],
        notes: ['No DDoS attacks'],
        rate_limit_requests: 10,
        rate_limit_seconds: 60,
        custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
      },
      updateFormData: mockUpdateFormData,
      currentStep: 6,
      nextStep: mockNextStep,
      prevStep: mockPrevStep,
      resetForm: mockResetForm,
      validationErrors: [],
      isSubmitting: false,
      submitError: 'Failed to create target',
      setValidationErrors: mockSetValidationErrors,
      clearValidationErrors: mockClearValidationErrors,
      setSubmitting: mockSetSubmitting,
      setSubmitError: mockSetSubmitError,
    });

    render(<TargetProfileBuilder />);
    
    expect(screen.getByText(/failed to create target/i)).toBeInTheDocument();
  });
}); 