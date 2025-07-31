import { render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import { DashboardPage } from '../DashboardPage';

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
  TargetProfileCard: () => <div data-testid="target-profile-card">Target Profile</div>,
}));

vi.mock('@/components/organisms/StageCard', () => ({
  StageCard: ({ title }: any) => <div data-testid="stage-card">{title}</div>,
}));

vi.mock('@/components/atoms/StartButton', () => ({
  StartButton: () => <button data-testid="start-button">Start</button>,
}));

vi.mock('@/components/organisms/OverlayManager', () => ({
  OverlayManager: ({ children }: any) => <div data-testid="overlay-manager">{children}</div>,
}));

describe('DashboardPage', () => {
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
}); 