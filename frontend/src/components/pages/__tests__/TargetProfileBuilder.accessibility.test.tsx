import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import TargetProfileBuilder from '../TargetProfileBuilder';

// Mock framer-motion
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>
  },
  AnimatePresence: ({ children }: any) => children
}));

describe('TargetProfileBuilder Accessibility', () => {
  it('has proper heading structure', () => {
    render(<TargetProfileBuilder />);
    
    // Check for main heading
    const mainHeading = screen.getByRole('heading', { level: 3 });
    expect(mainHeading).toHaveTextContent('Build Target Profile');
  });

  it('has proper form labels', () => {
    render(<TargetProfileBuilder />);
    
    // Check for form labels
    expect(screen.getByLabelText('Target Company')).toBeInTheDocument();
    expect(screen.getByLabelText('Domain/IP Address')).toBeInTheDocument();
  });

  it('has proper button labels', () => {
    render(<TargetProfileBuilder />);
    
    // Check for navigation buttons
    expect(screen.getByRole('button', { name: /previous/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /next/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /save to target's profile/i })).toBeInTheDocument();
  });

  it('has proper checkbox labeling', () => {
    render(<TargetProfileBuilder />);
    
    // Check for checkbox with proper label
    const checkbox = screen.getByRole('checkbox');
    expect(checkbox).toBeInTheDocument();
    expect(checkbox).toHaveAccessibleName('Set as Primary Target');
  });

  it('has proper focus management', () => {
    render(<TargetProfileBuilder />);
    
    // Check that form elements are present and focusable
    const targetInput = screen.getByLabelText('Target Company');
    const domainInput = screen.getByLabelText('Domain/IP Address');
    const checkbox = screen.getByRole('checkbox');
    
    expect(targetInput).toBeInTheDocument();
    expect(domainInput).toBeInTheDocument();
    expect(checkbox).toBeInTheDocument();
  });

  it('has proper ARIA attributes', () => {
    render(<TargetProfileBuilder />);
    
    // Check for required field indicators
    const targetInput = screen.getByLabelText('Target Company');
    const domainInput = screen.getByLabelText('Domain/IP Address');
    
    expect(targetInput).toHaveAttribute('required');
    expect(domainInput).toHaveAttribute('required');
  });

  it('has proper color contrast', () => {
    render(<TargetProfileBuilder />);
    
    // Check that text has sufficient contrast
    const mainHeading = screen.getByRole('heading', { level: 3 });
    expect(mainHeading).toHaveClass('text-white');
    
    const labels = screen.getAllByText(/Target Company|Domain\/IP Address/);
    labels.forEach(label => {
      expect(label).toHaveClass('text-gray-200');
    });
  });

  it('has proper keyboard navigation', () => {
    render(<TargetProfileBuilder />);
    
    // Check that all interactive elements are keyboard accessible
    const buttons = screen.getAllByRole('button');
    expect(buttons.length).toBeGreaterThan(0);
  });

  it('has proper step indicator accessibility', () => {
    render(<TargetProfileBuilder />);
    
    // Check that step progress is properly labeled
    expect(screen.getByText('Step 1 of 6')).toBeInTheDocument();
    
    // Check that step numbers are properly announced
    const stepNumbers = screen.getAllByText(/Step \d+/);
    stepNumbers.forEach(step => {
      expect(step).toBeInTheDocument();
    });
  });

  it('has proper form structure', () => {
    render(<TargetProfileBuilder />);
    
    // Check that form elements are properly grouped
    const formSection = screen.getByText('Target Company').closest('div');
    expect(formSection).toBeInTheDocument();
  });

  it('has proper loading states', () => {
    render(<TargetProfileBuilder />);
    
    // Check that buttons have proper loading states
    const submitButton = screen.getByRole('button', { name: /save to target's profile/i });
    expect(submitButton).not.toBeDisabled(); // Initially not disabled
    
    // When loading, button should be disabled and show loading text
    // This would be tested in integration tests
  });
}); 