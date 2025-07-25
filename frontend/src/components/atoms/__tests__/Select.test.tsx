import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Select from '../Select';

const mockOptions = [
  { value: 'option1', label: 'Option 1' },
  { value: 'option2', label: 'Option 2' },
  { value: 'option3', label: 'Option 3' },
];

describe('Select Component', () => {
  it('renders with label and options', () => {
    render(<Select label="Choose Option" options={mockOptions} />);
    expect(screen.getByLabelText(/choose option/i)).toBeInTheDocument();
    expect(screen.getByDisplayValue(/option 1/i)).toBeInTheDocument();
  });

  it('renders without label', () => {
    render(<Select options={mockOptions} />);
    expect(screen.getByRole('combobox')).toBeInTheDocument();
  });

  it('handles value changes', () => {
    const handleChange = vi.fn();
    render(<Select label="Choose Option" options={mockOptions} onChange={handleChange} />);
    const select = screen.getByLabelText(/choose option/i);
    
    fireEvent.change(select, { target: { value: 'option2' } });
    expect(handleChange).toHaveBeenCalledWith(
      expect.objectContaining({
        target: expect.objectContaining({ value: 'option2' })
      })
    );
  });

  it('displays error message', () => {
    render(<Select label="Choose Option" options={mockOptions} error="Please select an option" />);
    expect(screen.getByText(/please select an option/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/choose option/i)).toHaveClass('border-red-500');
  });

  it('can be disabled', () => {
    render(<Select label="Choose Option" options={mockOptions} disabled />);
    const select = screen.getByLabelText(/choose option/i);
    expect(select).toBeDisabled();
    expect(select).toHaveClass('opacity-50', 'cursor-not-allowed');
  });

  it('renders with placeholder option', () => {
    const optionsWithPlaceholder = [
      { value: '', label: 'Select an option' },
      ...mockOptions,
    ];
    render(<Select label="Choose Option" options={optionsWithPlaceholder} />);
    expect(screen.getByDisplayValue(/select an option/i)).toBeInTheDocument();
  });

  it('renders with custom className on wrapper', () => {
    render(<Select label="Choose Option" options={mockOptions} className="custom-select" />);
    const wrapper = screen.getByLabelText(/choose option/i).closest('div');
    expect(wrapper).toHaveClass('custom-select');
  });

  it('renders with required attribute', () => {
    render(<Select label="Choose Option" options={mockOptions} required />);
    const select = screen.getByLabelText(/choose option/i);
    expect(select).toBeRequired();
  });

  it('renders with id attribute', () => {
    render(<Select label="Choose Option" options={mockOptions} id="custom-select" />);
    const select = screen.getByLabelText(/choose option/i);
    expect(select).toHaveAttribute('id', 'custom-select');
  });

  it('handles onBlur events', () => {
    const handleBlur = vi.fn();
    render(<Select label="Choose Option" options={mockOptions} onBlur={handleBlur} />);
    const select = screen.getByLabelText(/choose option/i);
    
    fireEvent.blur(select);
    expect(handleBlur).toHaveBeenCalledTimes(1);
  });

  it('handles onFocus events', () => {
    const handleFocus = vi.fn();
    render(<Select label="Choose Option" options={mockOptions} onFocus={handleFocus} />);
    const select = screen.getByLabelText(/choose option/i);
    
    fireEvent.focus(select);
    expect(handleFocus).toHaveBeenCalledTimes(1);
  });

  it('renders with helper text', () => {
    render(<Select label="Choose Option" options={mockOptions} helperText="Select the best option" />);
    expect(screen.getByText(/select the best option/i)).toBeInTheDocument();
  });

  it('renders with icon', () => {
    render(<Select label="Choose Option" options={mockOptions} icon={<span data-testid="icon">🔽</span>} />);
    const icon = screen.getByTestId('icon');
    expect(icon).toBeInTheDocument();
  });

  it('renders with default value', () => {
    render(<Select label="Choose Option" options={mockOptions} defaultValue="option2" />);
    expect(screen.getByDisplayValue(/option 2/i)).toBeInTheDocument();
  });

  it('renders with value prop', () => {
    render(<Select label="Choose Option" options={mockOptions} value="option3" />);
    expect(screen.getByDisplayValue(/option 3/i)).toBeInTheDocument();
  });
}); 