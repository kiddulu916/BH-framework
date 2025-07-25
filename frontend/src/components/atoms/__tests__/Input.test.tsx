import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Input from '../Input';

describe('Input Component', () => {
  it('renders with label', () => {
    render(<Input label="Email" placeholder="Enter your email" />);
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/enter your email/i)).toBeInTheDocument();
  });

  it('renders without label', () => {
    render(<Input placeholder="Enter your email" />);
    expect(screen.getByPlaceholderText(/enter your email/i)).toBeInTheDocument();
  });

  it('handles value changes', () => {
    const handleChange = vi.fn();
    render(<Input label="Email" onChange={handleChange} />);
    const input = screen.getByLabelText(/email/i);
    
    fireEvent.change(input, { target: { value: 'test@example.com' } });
    expect(handleChange).toHaveBeenCalledWith(
      expect.objectContaining({
        target: expect.objectContaining({ value: 'test@example.com' })
      })
    );
  });

  it('displays error message', () => {
    render(<Input label="Email" error="Invalid email format" />);
    expect(screen.getByText(/invalid email format/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/email/i)).toHaveClass('border-red-500');
  });

  it('can be disabled', () => {
    render(<Input label="Email" disabled />);
    const input = screen.getByLabelText(/email/i);
    expect(input).toBeDisabled();
    expect(input).toHaveClass('opacity-50', 'cursor-not-allowed');
  });

  it('renders with different types', () => {
    render(<Input label="Password" type="password" />);
    const input = screen.getByLabelText(/password/i);
    expect(input).toHaveAttribute('type', 'password');
  });

  it('renders with custom className on wrapper', () => {
    render(<Input label="Email" className="custom-input" />);
    const wrapper = screen.getByLabelText(/email/i).closest('div');
    expect(wrapper).toHaveClass('custom-input');
  });

  it('renders with required attribute', () => {
    render(<Input label="Email" required />);
    const input = screen.getByLabelText(/email/i);
    expect(input).toBeRequired();
  });

  it('renders with id attribute', () => {
    render(<Input label="Email" id="email-input" />);
    const input = screen.getByLabelText(/email/i);
    expect(input).toHaveAttribute('id', 'email-input');
  });

  it('handles onBlur events', () => {
    const handleBlur = vi.fn();
    render(<Input label="Email" onBlur={handleBlur} />);
    const input = screen.getByLabelText(/email/i);
    
    fireEvent.blur(input);
    expect(handleBlur).toHaveBeenCalledTimes(1);
  });

  it('handles onFocus events', () => {
    const handleFocus = vi.fn();
    render(<Input label="Email" onFocus={handleFocus} />);
    const input = screen.getByLabelText(/email/i);
    
    fireEvent.focus(input);
    expect(handleFocus).toHaveBeenCalledTimes(1);
  });

  it('renders with helper text', () => {
    render(<Input label="Email" helperText="We'll never share your email" />);
    expect(screen.getByText(/we'll never share your email/i)).toBeInTheDocument();
  });

  it('renders with icon', () => {
    render(<Input label="Email" icon={<span data-testid="icon">📧</span>} />);
    const icon = screen.getByTestId('icon');
    expect(icon).toBeInTheDocument();
  });
}); 