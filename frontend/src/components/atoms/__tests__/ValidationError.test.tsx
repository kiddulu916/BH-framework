import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import ValidationError from '../ValidationError';

describe('ValidationError Component', () => {
  it('renders single error message correctly', () => {
    const errors = ['This field is required'];
    render(<ValidationError errors={errors} />);

    expect(screen.getByText('This field is required')).toBeInTheDocument();
    expect(screen.getByTestId('alert-circle-icon')).toBeInTheDocument();
  });

  it('renders multiple error messages correctly', () => {
    const errors = [
      'This field is required',
      'Invalid email format',
      'Must be at least 3 characters'
    ];
    render(<ValidationError errors={errors} />);

    expect(screen.getByText('This field is required')).toBeInTheDocument();
    expect(screen.getByText('Invalid email format')).toBeInTheDocument();
    expect(screen.getByText('Must be at least 3 characters')).toBeInTheDocument();
    expect(screen.getAllByTestId('alert-circle-icon')).toHaveLength(3);
  });

  it('renders nothing when no errors provided', () => {
    render(<ValidationError errors={[]} />);
    
    expect(screen.queryByText('This field is required')).not.toBeInTheDocument();
    expect(screen.queryByTestId('alert-circle-icon')).not.toBeInTheDocument();
  });

  it('renders nothing when errors is null', () => {
    render(<ValidationError errors={null as any} />);
    
    expect(screen.queryByText('This field is required')).not.toBeInTheDocument();
    expect(screen.queryByTestId('alert-circle-icon')).not.toBeInTheDocument();
  });

  it('renders nothing when errors is undefined', () => {
    render(<ValidationError errors={undefined as any} />);
    
    expect(screen.queryByText('This field is required')).not.toBeInTheDocument();
    expect(screen.queryByTestId('alert-circle-icon')).not.toBeInTheDocument();
  });
}); 