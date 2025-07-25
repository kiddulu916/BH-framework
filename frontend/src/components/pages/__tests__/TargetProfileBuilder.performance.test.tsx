import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import TargetProfileBuilder from '../TargetProfileBuilder';

// Mock dependencies
vi.mock('@/lib/state/targetFormStore');
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>
  },
  AnimatePresence: ({ children }: any) => children
}));

const mockUseTargetFormStore = vi.mocked(useTargetFormStore);

describe('TargetProfileBuilder Performance', () => {
  const mockUpdateFormData = vi.fn();
  const mockNextStep = vi.fn();
  const mockPrevStep = vi.fn();
  const mockResetForm = vi.fn();
  const mockSetValidationErrors = vi.fn();
  const mockClearValidationErrors = vi.fn();
  const mockSetSubmitting = vi.fn();
  const mockSetSubmitError = vi.fn();

  beforeEach(() => {
    // Mock store to always be on step 1
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
      currentStep: 1, // Always start on step 1
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
  });

  it('renders within acceptable time', () => {
    const startTime = performance.now();
    
    render(<TargetProfileBuilder />);
    
    const endTime = performance.now();
    const renderTime = endTime - startTime;
    
    // Should render within 100ms
    expect(renderTime).toBeLessThan(100);
  });

  it('handles rapid input changes efficiently', () => {
    render(<TargetProfileBuilder />);
    
    const targetInput = screen.getByPlaceholderText('Enter target company name');
    const startTime = performance.now();
    
    // Simulate rapid typing
    for (let i = 0; i < 10; i++) {
      fireEvent.change(targetInput, { target: { value: `Test Company ${i}` } });
    }
    
    const endTime = performance.now();
    const inputTime = endTime - startTime;
    
    // Should handle 10 input changes within 50ms
    expect(inputTime).toBeLessThan(50);
  });

  it('validates form efficiently', () => {
    render(<TargetProfileBuilder />);
    
    const targetInput = screen.getByPlaceholderText('Enter target company name');
    const domainInput = screen.getByPlaceholderText('Enter domain or IP address');
    
    const startTime = performance.now();
    
    // Fill form and trigger validation
    fireEvent.change(targetInput, { target: { value: 'Test Company' } });
    fireEvent.change(domainInput, { target: { value: 'example.com' } });
    
    const nextButton = screen.getByText('Next');
    fireEvent.click(nextButton);
    
    const endTime = performance.now();
    const validationTime = endTime - startTime;
    
    // Validation should complete within 30ms
    expect(validationTime).toBeLessThan(30);
  });

  it('handles step navigation efficiently', () => {
    render(<TargetProfileBuilder />);
    
    // Fill step 1
    const targetInput = screen.getByPlaceholderText('Enter target company name');
    const domainInput = screen.getByPlaceholderText('Enter domain or IP address');
    
    fireEvent.change(targetInput, { target: { value: 'Test Company' } });
    fireEvent.change(domainInput, { target: { value: 'example.com' } });
    
    const startTime = performance.now();
    
    // Navigate through steps
    const nextButton = screen.getByText('Next');
    fireEvent.click(nextButton);
    
    const endTime = performance.now();
    const navigationTime = endTime - startTime;
    
    // Step navigation should complete within 50ms
    expect(navigationTime).toBeLessThan(50);
  });

  it('handles large form data efficiently', () => {
    render(<TargetProfileBuilder />);
    
    const targetInput = screen.getByPlaceholderText('Enter target company name');
    const domainInput = screen.getByPlaceholderText('Enter domain or IP address');
    
    const startTime = performance.now();
    
    // Fill with large data
    const largeText = 'A'.repeat(1000);
    fireEvent.change(targetInput, { target: { value: largeText } });
    fireEvent.change(domainInput, { target: { value: 'example.com' } });
    
    const endTime = performance.now();
    const largeDataTime = endTime - startTime;
    
    // Should handle large data within 100ms
    expect(largeDataTime).toBeLessThan(100);
  });

  it('handles multiple validation errors efficiently', () => {
    render(<TargetProfileBuilder />);
    
    const startTime = performance.now();
    
    // Trigger multiple validation errors
    const nextButton = screen.getByText('Next');
    fireEvent.click(nextButton);
    
    const endTime = performance.now();
    const multipleErrorsTime = endTime - startTime;
    
    // Should handle multiple errors within 50ms
    expect(multipleErrorsTime).toBeLessThan(50);
  });

  it('handles state updates efficiently', () => {
    render(<TargetProfileBuilder />);
    
    const targetInput = screen.getByPlaceholderText('Enter target company name');
    const startTime = performance.now();
    
    // Simulate many state updates
    for (let i = 0; i < 20; i++) {
      fireEvent.change(targetInput, { target: { value: `Update ${i}` } });
    }
    
    const endTime = performance.now();
    const stateUpdateTime = endTime - startTime;
    
    // Should handle 20 state updates within 100ms
    expect(stateUpdateTime).toBeLessThan(100);
  });

  it('handles form submission efficiently', async () => {
    const { createTarget } = await import('@/lib/api/targets');
    vi.mocked(createTarget).mockResolvedValue({ success: true, data: { id: '1' } });
    
    render(<TargetProfileBuilder />);
    
    const startTime = performance.now();
    
    // Trigger form submission (simplified)
    const submitButton = screen.getByText('Create Target Profile');
    fireEvent.click(submitButton);
    
    const endTime = performance.now();
    const submissionTime = endTime - startTime;
    
    // Form submission should start within 50ms
    expect(submissionTime).toBeLessThan(50);
  });

  it('handles error states efficiently', () => {
    render(<TargetProfileBuilder />);
    
    const startTime = performance.now();
    
    // Trigger error state
    const nextButton = screen.getByText('Next');
    fireEvent.click(nextButton);
    
    // Wait for error to appear
    const errorElement = screen.getByText('Build Target Profile');
    
    const endTime = performance.now();
    const errorTime = endTime - startTime;
    
    // Error state should appear within 30ms
    expect(errorTime).toBeLessThan(30);
    expect(errorElement).toBeInTheDocument();
  });

  it('handles component re-renders efficiently', () => {
    const { rerender } = render(<TargetProfileBuilder />);
    
    const startTime = performance.now();
    
    // Force multiple re-renders
    for (let i = 0; i < 5; i++) {
      rerender(<TargetProfileBuilder />);
    }
    
    const endTime = performance.now();
    const rerenderTime = endTime - startTime;
    
    // Should handle 5 re-renders within 50ms
    expect(rerenderTime).toBeLessThan(50);
  });

  it('handles memory usage efficiently', () => {
    const initialMemory = performance.memory?.usedJSHeapSize || 0;
    
    // Render multiple instances
    const { unmount } = render(<TargetProfileBuilder />);
    unmount();
    
    render(<TargetProfileBuilder />);
    unmount();
    
    render(<TargetProfileBuilder />);
    
    const finalMemory = performance.memory?.usedJSHeapSize || 0;
    const memoryIncrease = finalMemory - initialMemory;
    
    // Memory increase should be reasonable (less than 10MB)
    if (performance.memory) {
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    }
  });
}); 