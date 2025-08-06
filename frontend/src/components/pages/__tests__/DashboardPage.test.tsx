import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { vi, beforeEach, describe, it, expect } from 'vitest';
import { DashboardPage } from '../DashboardPage';
import { TargetStatus } from '@/types/target';

// Mock the API functions
vi.mock('@/lib/api/targets', () => ({
  getTargets: vi.fn(),
  updateTarget: vi.fn(),
}));

vi.mock('@/lib/api/stages', () => ({
  getStageSummary: vi.fn(),
  startPassiveRecon: vi.fn(),
  startActiveRecon: vi.fn(),
  getPassiveReconStatus: vi.fn(),
  getActiveReconStatus: vi.fn(),
}));

// Mock the components to avoid complex testing setup
vi.mock('@/components/organisms/Header', () => ({
  Header: ({ onNavigationClick, onSettingsClick }: any) => (
    <header>
      <button onClick={onNavigationClick}>Navigation</button>
      <button onClick={onSettingsClick}>Settings</button>
    </header>
  ),
}));

vi.mock('@/components/organisms/TargetProfileCard', () => ({
  TargetProfileCard: ({ target }: any) => (
    <div data-testid="target-profile-card">
      Target Profile: {target?.domain || 'No target'}
    </div>
  ),
}));

vi.mock('@/components/organisms/StageCard', () => ({
  StageCard: ({ 
    id, 
    title, 
    isStageSelected, 
    selectedTools, 
    onToolChange, 
    onStageSelectionChange, 
    onStartStage,
    isRunning 
  }: any) => (
    <div data-testid={`stage-card-${id}`}>
      <div>{title}</div>
      <input
        type="checkbox"
        checked={isStageSelected}
        onChange={(e) => onStageSelectionChange?.(e.target.checked)}
        data-testid={`stage-checkbox-${id}`}
      />
      <button
        onClick={() => onStartStage?.(id, selectedTools || [])}
        disabled={isRunning}
        data-testid={`start-stage-${id}`}
      >
        Start {title}
      </button>
      <div data-testid={`selected-tools-${id}`}>
        {selectedTools?.length || 0} tools selected
      </div>
    </div>
  ),
}));

vi.mock('@/components/atoms/StartButton', () => ({
  StartButton: ({ onClick, disabled }: any) => (
    <button 
      onClick={onClick} 
      disabled={disabled}
      data-testid="start-button"
    >
      Start
    </button>
  ),
}));

vi.mock('@/components/organisms/OverlayManager', () => ({
  OverlayManager: ({ children }: any) => <div data-testid="overlay-manager">{children}</div>,
}));

// Import the mocked functions
import { getTargets, updateTarget } from '@/lib/api/targets';
import { 
  getStageSummary, 
  startPassiveRecon, 
  startActiveRecon,
  getPassiveReconStatus,
  getActiveReconStatus 
} from '@/lib/api/stages';

describe('DashboardPage', () => {
  const mockPrimaryTarget = {
    id: 'test-target-id',
    target: 'Test Company',
    domain: 'test.com',
    status: TargetStatus.ACTIVE,
    is_primary: true,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z'
  };

  const mockStageData = {
    passive_recon: { results: [], count: 0 },
    active_recon: { results: [], count: 0 },
    recursive_recon: { results: null, has_data: false }
  };

  const mockStageStatus = {
    status: 'completed',
    total_tools: 5,
    completed_tools: 5,
    error: null
  };

  beforeEach(() => {
    vi.clearAllMocks();
    
    // Default mock implementations
    (getTargets as any).mockResolvedValue({
      success: true,
      data: { items: [mockPrimaryTarget] }
    });
    
    (updateTarget as any).mockResolvedValue({
      success: true,
      data: mockPrimaryTarget
    });
    
    (getStageSummary as any).mockResolvedValue(mockStageData);
    (getPassiveReconStatus as any).mockResolvedValue(mockStageStatus);
    (getActiveReconStatus as any).mockResolvedValue(mockStageStatus);
    (startPassiveRecon as any).mockResolvedValue({ success: true });
    (startActiveRecon as any).mockResolvedValue({ success: true });
  });

  it('renders dashboard components', () => {
    render(<DashboardPage />);
    
    expect(screen.getByTestId('target-profile-card')).toBeInTheDocument();
    expect(screen.getByTestId('start-button')).toBeInTheDocument();
    expect(screen.getByTestId('overlay-manager')).toBeInTheDocument();
  });

  it('renders all stage cards', () => {
    render(<DashboardPage />);
    
    expect(screen.getByText('Passive Recon')).toBeInTheDocument();
    expect(screen.getByText('Active Recon')).toBeInTheDocument();
    expect(screen.getByText('Vulnerability Scanning')).toBeInTheDocument();
    expect(screen.getByText('Vulnerability Testing')).toBeInTheDocument();
    expect(screen.getByText('Kill Chain')).toBeInTheDocument();
    expect(screen.getByText('Report Generation')).toBeInTheDocument();
  });

  it('fetches primary target on mount', async () => {
    render(<DashboardPage />);
    
    await waitFor(() => {
      expect(getTargets).toHaveBeenCalledWith({
        is_primary: true,
        status: TargetStatus.ACTIVE
      });
    });
  });

  it('displays primary target information', async () => {
    render(<DashboardPage />);
    
    await waitFor(() => {
      expect(screen.getByText('Target Profile: test.com')).toBeInTheDocument();
    });
  });

  it('sets target as active if not already active', async () => {
    const inactiveTarget = { ...mockPrimaryTarget, status: TargetStatus.INACTIVE };
    (getTargets as any).mockResolvedValue({
      success: true,
      data: { items: [inactiveTarget] }
    });

    render(<DashboardPage />);
    
    await waitFor(() => {
      expect(updateTarget).toHaveBeenCalledWith(inactiveTarget.id, {
        status: TargetStatus.ACTIVE
      });
    });
  });

  it('handles primary target fetch error gracefully', async () => {
    (getTargets as any).mockRejectedValue(new Error('API Error'));
    
    render(<DashboardPage />);
    
    // Should not crash and should show no target
    await waitFor(() => {
      expect(screen.getByText('Target Profile: No target')).toBeInTheDocument();
    });
  });

  it('renders stage checkboxes with default selection', () => {
    render(<DashboardPage />);
    
    // All stages should be selected by default
    expect(screen.getByTestId('stage-checkbox-passive-recon')).toBeChecked();
    expect(screen.getByTestId('stage-checkbox-active-recon')).toBeChecked();
    expect(screen.getByTestId('stage-checkbox-vulnerability-scanning')).toBeChecked();
    expect(screen.getByTestId('stage-checkbox-vulnerability-testing')).toBeChecked();
    expect(screen.getByTestId('stage-checkbox-kill-chain')).toBeChecked();
    expect(screen.getByTestId('stage-checkbox-report-generation')).toBeChecked();
  });

  it('allows stage selection changes', async () => {
    render(<DashboardPage />);
    
    const passiveCheckbox = screen.getByTestId('stage-checkbox-passive-recon');
    
    // Uncheck the passive recon stage
    fireEvent.click(passiveCheckbox);
    
    expect(passiveCheckbox).not.toBeChecked();
  });

  it('shows selected tools count for each stage', () => {
    render(<DashboardPage />);
    
    // By default, no specific tools are selected (empty array means all tools)
    expect(screen.getByTestId('selected-tools-passive-recon')).toHaveTextContent('0 tools selected');
    expect(screen.getByTestId('selected-tools-active-recon')).toHaveTextContent('0 tools selected');
  });

  it('enables start button when primary target is available', async () => {
    render(<DashboardPage />);
    
    await waitFor(() => {
      const startButton = screen.getByTestId('start-button');
      expect(startButton).not.toBeDisabled();
    });
  });

  it('disables start button when no primary target is available', () => {
    (getTargets as any).mockResolvedValue({
      success: true,
      data: { items: [] }
    });
    
    render(<DashboardPage />);
    
    const startButton = screen.getByTestId('start-button');
    expect(startButton).toBeDisabled();
  });

  it('executes workflow when start button is clicked', async () => {
    render(<DashboardPage />);
    
    await waitFor(() => {
      const startButton = screen.getByTestId('start-button');
      expect(startButton).not.toBeDisabled();
    });
    
    const startButton = screen.getByTestId('start-button');
    fireEvent.click(startButton);
    
    await waitFor(() => {
      // Should start all selected stages
      expect(startPassiveRecon).toHaveBeenCalled();
      expect(startActiveRecon).toHaveBeenCalled();
    });
  });

  it('shows error when no stages are selected', async () => {
    render(<DashboardPage />);
    
    // Uncheck all stages
    fireEvent.click(screen.getByTestId('stage-checkbox-passive-recon'));
    fireEvent.click(screen.getByTestId('stage-checkbox-active-recon'));
    fireEvent.click(screen.getByTestId('stage-checkbox-vulnerability-scanning'));
    fireEvent.click(screen.getByTestId('stage-checkbox-vulnerability-testing'));
    fireEvent.click(screen.getByTestId('stage-checkbox-kill-chain'));
    fireEvent.click(screen.getByTestId('stage-checkbox-report-generation'));
    
    const startButton = screen.getByTestId('start-button');
    fireEvent.click(startButton);
    
    await waitFor(() => {
      expect(screen.getByText('Please select at least one stage to run')).toBeInTheDocument();
    });
  });

  it('shows error when no primary target is found', async () => {
    (getTargets as any).mockResolvedValue({
      success: true,
      data: { items: [] }
    });
    
    render(<DashboardPage />);
    
    await waitFor(() => {
      const startButton = screen.getByTestId('start-button');
      fireEvent.click(startButton);
    });
    
    await waitFor(() => {
      expect(screen.getByText('No primary target found')).toBeInTheDocument();
    });
  });

  it('handles workflow execution errors gracefully', async () => {
    (startPassiveRecon as any).mockRejectedValue(new Error('Stage failed'));
    
    render(<DashboardPage />);
    
    await waitFor(() => {
      const startButton = screen.getByTestId('start-button');
      fireEvent.click(startButton);
    });
    
    await waitFor(() => {
      expect(screen.getByText('Failed to start passive-recon')).toBeInTheDocument();
    });
  });

  it('fetches stage data when primary target is available', async () => {
    render(<DashboardPage />);
    
    await waitFor(() => {
      expect(getStageSummary).toHaveBeenCalledWith('test-target-id');
      expect(getPassiveReconStatus).toHaveBeenCalledWith('test-target-id');
      expect(getActiveReconStatus).toHaveBeenCalledWith('test-target-id');
    });
  });

  it('handles "All" checkbox behavior correctly', async () => {
    render(<DashboardPage />);
    
    // By default, "All" should be selected (empty array means all tools)
    expect(screen.getByTestId('selected-tools-passive-recon')).toHaveTextContent('0 tools selected');
    
    // Simulate unchecking "All" checkbox
    const passiveStageCard = screen.getByTestId('stage-card-passive-recon');
    const allCheckbox = passiveStageCard.querySelector('input[type="checkbox"]');
    
    if (allCheckbox) {
      fireEvent.click(allCheckbox);
    }
    
    // After unchecking "All", individual tools should be selectable
    // The selected tools count should remain 0 until individual tools are selected
    expect(screen.getByTestId('selected-tools-passive-recon')).toHaveTextContent('0 tools selected');
  });
}); 