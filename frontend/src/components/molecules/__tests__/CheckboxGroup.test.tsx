import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CheckboxGroup } from '../CheckboxGroup';

describe('CheckboxGroup', () => {
  const mockTools = ['Tool1', 'Tool2', 'Tool3'];
  const mockOnToolChange = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders "All" checkbox and individual tool checkboxes', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={[]}
        onToolChange={mockOnToolChange}
      />
    );

    expect(screen.getByText(/All/)).toBeInTheDocument();
    expect(screen.getByText('Tool1')).toBeInTheDocument();
    expect(screen.getByText('Tool2')).toBeInTheDocument();
    expect(screen.getByText('Tool3')).toBeInTheDocument();
  });

  it('shows "All" checkbox as checked when selectedTools is empty', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={[]}
        onToolChange={mockOnToolChange}
      />
    );

    const allCheckbox = screen.getByRole('checkbox', { name: /all/i });
    expect(allCheckbox).toBeChecked();
  });

  it('shows "All" checkbox as unchecked when individual tools are selected', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={['Tool1', 'Tool2']}
        onToolChange={mockOnToolChange}
      />
    );

    const allCheckbox = screen.getByRole('checkbox', { name: /all/i });
    expect(allCheckbox).not.toBeChecked();
  });

  it('disables individual tool checkboxes when "All" is selected', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={[]}
        onToolChange={mockOnToolChange}
      />
    );

    const tool1Checkbox = screen.getByRole('checkbox', { name: /tool1/i });
    const tool2Checkbox = screen.getByRole('checkbox', { name: /tool2/i });
    const tool3Checkbox = screen.getByRole('checkbox', { name: /tool3/i });

    expect(tool1Checkbox).toBeDisabled();
    expect(tool2Checkbox).toBeDisabled();
    expect(tool3Checkbox).toBeDisabled();
  });

  it('enables individual tool checkboxes when "All" is not selected', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={['Tool1']}
        onToolChange={mockOnToolChange}
      />
    );

    const tool1Checkbox = screen.getByRole('checkbox', { name: /tool1/i });
    const tool2Checkbox = screen.getByRole('checkbox', { name: /tool2/i });
    const tool3Checkbox = screen.getByRole('checkbox', { name: /tool3/i });

    expect(tool1Checkbox).not.toBeDisabled();
    expect(tool2Checkbox).not.toBeDisabled();
    expect(tool3Checkbox).not.toBeDisabled();
  });

  it('calls onToolChange with "All" when "All" checkbox is clicked', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={[]}
        onToolChange={mockOnToolChange}
      />
    );

    const allCheckbox = screen.getByRole('checkbox', { name: /all/i });
    fireEvent.click(allCheckbox);

    expect(mockOnToolChange).toHaveBeenCalledWith('All', false);
  });

  it('calls onToolChange with individual tool when tool checkbox is clicked', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={['Tool1']}
        onToolChange={mockOnToolChange}
      />
    );

    const tool2Checkbox = screen.getByRole('checkbox', { name: /tool2/i });
    fireEvent.click(tool2Checkbox);

    expect(mockOnToolChange).toHaveBeenCalledWith('Tool2', true);
  });

  it('shows individual tools as checked when they are in selectedTools', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={['Tool1', 'Tool3']}
        onToolChange={mockOnToolChange}
      />
    );

    const tool1Checkbox = screen.getByRole('checkbox', { name: /tool1/i });
    const tool2Checkbox = screen.getByRole('checkbox', { name: /tool2/i });
    const tool3Checkbox = screen.getByRole('checkbox', { name: /tool3/i });

    expect(tool1Checkbox).toBeChecked();
    expect(tool2Checkbox).not.toBeChecked();
    expect(tool3Checkbox).toBeChecked();
  });

  it('allows deselecting "All" checkbox to enable individual selection', () => {
    render(
      <CheckboxGroup
        tools={mockTools}
        selectedTools={[]}
        onToolChange={mockOnToolChange}
      />
    );

    const allCheckbox = screen.getByRole('checkbox', { name: /all/i });
    
    // Initially "All" is selected and individual tools are disabled
    expect(allCheckbox).toBeChecked();
    expect(screen.getByRole('checkbox', { name: /tool1/i })).toBeDisabled();
    
    // Click "All" to deselect it
    fireEvent.click(allCheckbox);
    
    // Should call onToolChange with "All" and false
    expect(mockOnToolChange).toHaveBeenCalledWith('All', false);
  });
}); 