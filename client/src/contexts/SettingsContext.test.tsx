import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SettingsProvider, useSettings, COLOR_SCHEMES } from './SettingsContext';
import { ReactNode } from 'react';

// Test component that uses the settings context
function TestComponent() {
  const { settings, colorScheme } = useSettings();
  return (
    <div>
      <div data-testid="theme">{settings.theme}</div>
      <div data-testid="color-scheme">{settings.colorScheme}</div>
      <div data-testid="font-size">{settings.fontSize}</div>
      <div data-testid="background">{colorScheme.background}</div>
    </div>
  );
}

describe('SettingsContext', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('should provide default settings', () => {
    render(
      <SettingsProvider>
        <TestComponent />
      </SettingsProvider>
    );

    expect(screen.getByTestId('theme')).toHaveTextContent('dark');
    expect(screen.getByTestId('color-scheme')).toHaveTextContent('VS Code Dark');
    expect(screen.getByTestId('font-size')).toHaveTextContent('14');
  });

  it('should provide color scheme based on settings', () => {
    render(
      <SettingsProvider>
        <TestComponent />
      </SettingsProvider>
    );

    const background = screen.getByTestId('background');
    expect(background).toHaveTextContent(COLOR_SCHEMES['VS Code Dark'].background);
  });

  it('should throw error when used outside provider', () => {
    // Suppress console.error for this test
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => render(<TestComponent />)).toThrow(
      'useSettings must be used within a SettingsProvider'
    );

    consoleSpy.mockRestore();
  });
});
