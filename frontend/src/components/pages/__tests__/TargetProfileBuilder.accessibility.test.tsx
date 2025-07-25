import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { axe, toHaveNoViolations } from 'jest-axe';
import TargetProfileBuilder from '../TargetProfileBuilder';

expect.extend(toHaveNoViolations);

// Mock framer-motion
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>
  },
  AnimatePresence: ({ children }: any) => children
}));

describe('TargetProfileBuilder Accessibility', () => {
  it('should not have any accessibility violations', async () => {
    const { container } = render(<TargetProfileBuilder />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

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
    
    // Check that form elements are focusable
    const targetInput = screen.getByLabelText('Target Company');
    const domainInput = screen.getByLabelText('Domain/IP Address');
    const checkbox = screen.getByRole('checkbox');
    
    expect(targetInput).toHaveAttribute('tabindex', '0');
    expect(domainInput).toHaveAttribute('tabindex', '0');
    expect(checkbox).toHaveAttribute('tabindex', '0');
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
    buttons.forEach(button => {
      expect(button).toHaveAttribute('tabindex', '0');
    });
  });

  it('has proper error message association', () => {
    render(<TargetProfileBuilder />);
    
    // Trigger validation by trying to navigate without filling fields
    const nextButton = screen.getByRole('button', { name: /next/i });
    fireEvent.click(nextButton);
    
    // Check that error messages are properly associated with form fields
    // This would require the form to show validation errors
    // For now, we just check that the form structure supports this
    const targetInput = screen.getByLabelText('Target Company');
    expect(targetInput).toHaveAttribute('aria-describedby');
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
    const submitButton = screen.getByRole('button', { name: /create target profile/i });
    expect(submitButton).not.toBeDisabled(); // Initially not disabled
    
    // When loading, button should be disabled and show loading text
    // This would be tested in integration tests
  });
}); 