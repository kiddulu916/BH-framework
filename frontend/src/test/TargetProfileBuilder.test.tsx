import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import TargetProfileBuilder from '../components/pages/TargetProfileBuilder';
import * as api from '@/lib/api/targets';

// Mock the API module
vi.mock('@/lib/api/targets', () => ({
  createTarget: vi.fn(),
}));

// Mock framer-motion
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <div>{children}</div>,
}));

describe('TargetProfileBuilder', () => {
  beforeEach(() => {
    // Reset the store before each test
    useTargetFormStore.getState().resetForm();
  });

  it('should render the form wizard', () => {
    render(<TargetProfileBuilder />);
    
    expect(screen.getByText(/build target profile/i)).toBeInTheDocument();
    expect(screen.getByText(/step 1 of 6/i)).toBeInTheDocument();
  });

  it('should navigate between steps', async () => {
    render(<TargetProfileBuilder />);

    // Fill step 1 data
    const targetInput = screen.getByLabelText(/target company/i);
    const domainInput = screen.getByLabelText(/domain\/ip address/i);
    
    fireEvent.change(targetInput, { target: { value: 'Test Company' } });
    fireEvent.change(domainInput, { target: { value: 'test.com' } });
    
    // Click Next
    const nextButton = screen.getByText(/next/i);
    fireEvent.click(nextButton);
    
    await waitFor(() => {
      expect(screen.getByText(/program details/i)).toBeInTheDocument();
    });
  });

  it('should save step data when save button is clicked', async () => {
    render(<TargetProfileBuilder />);

    // Fill step 1 data
    const targetInput = screen.getByLabelText(/target company/i);
    const domainInput = screen.getByLabelText(/domain\/ip address/i);
    
    fireEvent.change(targetInput, { target: { value: 'Test Company' } });
    fireEvent.change(domainInput, { target: { value: 'test.com' } });
    
    // Click Save Step Data
    const saveButton = screen.getByText(/save to target's profile/i);
    fireEvent.click(saveButton);
    
    await waitFor(() => {
      // Verify the data was saved to the store
      const formData = useTargetFormStore.getState().formData;
      expect(formData.target).toBe('Test Company');
      expect(formData.domain).toBe('test.com');
    });
  });
}); 