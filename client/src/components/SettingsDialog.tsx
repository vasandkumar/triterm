import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './ui/dialog';
import { Button } from './ui/button';
import { Separator } from './ui/separator';
import {
  Settings as SettingsIcon,
  Palette,
  Keyboard,
  Terminal as TerminalIcon,
  Shield,
  Check,
} from 'lucide-react';
import { useSettings, COLOR_SCHEMES } from '../contexts/SettingsContext';

export function SettingsDialog({ open, onOpenChange }) {
  const { settings, updateSettings, resetSettings } = useSettings();
  const [activeTab, setActiveTab] = useState('appearance');
  const [tempSettings, setTempSettings] = useState(settings);

  // Sync temp settings when dialog opens or settings change
  useEffect(() => {
    setTempSettings(settings);
  }, [settings, open]);

  const handleSave = () => {
    updateSettings(tempSettings);
    onOpenChange(false);
  };

  const handleCancel = () => {
    setTempSettings(settings);
    onOpenChange(false);
  };

  const updateTempSetting = (key, value) => {
    setTempSettings((prev) => ({ ...prev, [key]: value }));
  };

  const tabs = [
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'terminal', label: 'Terminal', icon: TerminalIcon },
    { id: 'keyboard', label: 'Keyboard', icon: Keyboard },
    { id: 'security', label: 'Security', icon: Shield },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <SettingsIcon className="h-5 w-5" />
            Settings
          </DialogTitle>
          <DialogDescription>Customize your TriTerm experience</DialogDescription>
        </DialogHeader>

        <div className="flex flex-1 gap-4 overflow-hidden">
          {/* Sidebar */}
          <div className="w-48 flex-shrink-0">
            <nav className="space-y-1">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                      activeTab === tab.id ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {tab.label}
                  </button>
                );
              })}
            </nav>
          </div>

          <Separator orientation="vertical" className="h-full" />

          {/* Content */}
          <div className="flex-1 overflow-y-auto pr-2">
            {activeTab === 'appearance' && (
              <AppearanceSettings settings={tempSettings} updateSetting={updateTempSetting} />
            )}
            {activeTab === 'terminal' && (
              <TerminalSettings settings={tempSettings} updateSetting={updateTempSetting} />
            )}
            {activeTab === 'keyboard' && <KeyboardSettings />}
            {activeTab === 'security' && (
              <SecuritySettings settings={tempSettings} updateSetting={updateTempSetting} />
            )}
          </div>
        </div>

        <div className="flex justify-between gap-2 pt-4 border-t">
          <Button variant="outline" onClick={resetSettings} className="text-destructive">
            Reset to Defaults
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleCancel}>
              Cancel
            </Button>
            <Button onClick={handleSave}>Save Changes</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function AppearanceSettings({ settings, updateSetting }) {
  const themes = [
    { id: 'dark', label: 'Dark', description: 'Dark theme' },
    { id: 'light', label: 'Light', description: 'Light theme' },
    { id: 'system', label: 'System', description: 'Follow system' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-2">Theme</h3>
        <p className="text-sm text-muted-foreground mb-4">Choose your preferred color theme</p>
        <div className="grid grid-cols-3 gap-3">
          {themes.map((theme) => (
            <button
              key={theme.id}
              onClick={() => updateSetting('theme', theme.id)}
              className={`p-4 border-2 rounded-lg transition-colors ${
                settings.theme === theme.id
                  ? 'border-primary bg-primary/5'
                  : 'border-muted hover:border-primary/50'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium">{theme.label}</div>
                {settings.theme === theme.id && <Check className="h-4 w-4 text-primary" />}
              </div>
              <div className="text-xs text-muted-foreground mt-1">{theme.description}</div>
            </button>
          ))}
        </div>
      </div>

      <Separator />

      <div>
        <h3 className="text-lg font-semibold mb-2">Terminal Colors</h3>
        <p className="text-sm text-muted-foreground mb-4">Customize terminal color scheme</p>
        <div className="grid grid-cols-2 gap-3">
          {Object.keys(COLOR_SCHEMES).map((scheme) => (
            <button
              key={scheme}
              onClick={() => updateSetting('colorScheme', scheme)}
              className={`p-3 border rounded-lg transition-colors text-left ${
                settings.colorScheme === scheme ? 'border-primary bg-primary/5' : 'hover:bg-muted'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium">{scheme}</div>
                {settings.colorScheme === scheme && <Check className="h-4 w-4 text-primary" />}
              </div>
              {/* Color preview */}
              <div className="flex gap-1 mt-2">
                {['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'].map(
                  (color) => (
                    <div
                      key={color}
                      className="h-4 w-4 rounded-sm"
                      style={{ backgroundColor: COLOR_SCHEMES[scheme][color] }}
                    />
                  )
                )}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function TerminalSettings({ settings, updateSetting }) {
  const fontFamilies = ['Fira Code', 'Monaco', 'Menlo', 'Courier New', 'Consolas'];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-2">Default Shell</h3>
        <p className="text-sm text-muted-foreground mb-4">
          Shell used for new terminals (server-configured)
        </p>
        <input
          type="text"
          className="w-full p-2 border rounded-md bg-muted"
          value="/bin/bash"
          disabled
          readOnly
        />
        <p className="text-xs text-muted-foreground mt-2">
          Configured on server. Contact administrator to change.
        </p>
      </div>

      <Separator />

      <div>
        <h3 className="text-lg font-semibold mb-2">Font Settings</h3>
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium flex items-center justify-between">
              <span>Font Size</span>
              <span className="text-primary">{settings.fontSize}px</span>
            </label>
            <input
              type="range"
              min="10"
              max="24"
              value={settings.fontSize}
              onChange={(e) => updateSetting('fontSize', parseInt(e.target.value))}
              className="w-full mt-2"
            />
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>10px</span>
              <span>14px</span>
              <span>24px</span>
            </div>
          </div>

          <div>
            <label className="text-sm font-medium">Font Family</label>
            <select
              className="w-full p-2 border rounded-md mt-2 bg-background"
              value={settings.fontFamily}
              onChange={(e) => updateSetting('fontFamily', e.target.value)}
            >
              {fontFamilies.map((font) => (
                <option key={font} value={font}>
                  {font}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <Separator />

      <div>
        <h3 className="text-lg font-semibold mb-2">Scrollback</h3>
        <p className="text-sm text-muted-foreground mb-4">Number of lines to keep in history</p>
        <input
          type="number"
          className="w-full p-2 border rounded-md bg-background"
          value={settings.scrollback}
          onChange={(e) => updateSetting('scrollback', parseInt(e.target.value))}
          min="1000"
          max="50000"
          step="1000"
        />
      </div>
    </div>
  );
}

function KeyboardSettings() {
  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-2">Keyboard Shortcuts</h3>
        <p className="text-sm text-muted-foreground mb-4">
          Common keyboard shortcuts (not yet customizable)
        </p>
        <div className="space-y-3">
          {[
            { action: 'New Terminal', shortcut: 'Ctrl+Shift+N' },
            { action: 'Close Terminal', shortcut: 'Ctrl+Shift+W' },
            { action: 'Next Terminal', shortcut: 'Ctrl+Tab' },
            { action: 'Previous Terminal', shortcut: 'Ctrl+Shift+Tab' },
            { action: 'Clear Terminal', shortcut: 'Ctrl+L' },
            { action: 'Copy', shortcut: 'Ctrl+Shift+C' },
            { action: 'Paste', shortcut: 'Ctrl+Shift+V' },
            { action: 'Find', shortcut: 'Ctrl+Shift+F' },
          ].map((item) => (
            <div
              key={item.action}
              className="flex items-center justify-between p-3 border rounded-lg"
            >
              <span className="text-sm font-medium">{item.action}</span>
              <kbd className="px-3 py-1.5 text-xs font-semibold bg-muted rounded border">
                {item.shortcut}
              </kbd>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function SecuritySettings({ settings, updateSetting }) {
  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-2">Connection Security</h3>
        <p className="text-sm text-muted-foreground mb-4">
          Current connection status and security settings
        </p>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 border rounded-lg bg-green-500/10">
            <div>
              <div className="text-sm font-medium">WebSocket Connection</div>
              <div className="text-xs text-muted-foreground">Secure connection established</div>
            </div>
            <div className="text-green-600 dark:text-green-400 font-semibold">Active</div>
          </div>
        </div>
      </div>

      <Separator />

      <div>
        <h3 className="text-lg font-semibold mb-2">Session Settings</h3>
        <div className="space-y-3">
          <label className="flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-muted/50">
            <div>
              <div className="text-sm font-medium">Auto-reconnect</div>
              <div className="text-xs text-muted-foreground">
                Automatically reconnect on connection loss
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.autoReconnect}
              onChange={(e) => updateSetting('autoReconnect', e.target.checked)}
              className="h-4 w-4"
            />
          </label>

          <label className="flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-muted/50">
            <div>
              <div className="text-sm font-medium">Clear on disconnect</div>
              <div className="text-xs text-muted-foreground">Clear terminals when disconnected</div>
            </div>
            <input
              type="checkbox"
              checked={settings.clearOnDisconnect}
              onChange={(e) => updateSetting('clearOnDisconnect', e.target.checked)}
              className="h-4 w-4"
            />
          </label>
        </div>
      </div>

      <Separator />

      <div>
        <h3 className="text-lg font-semibold mb-2">Privacy</h3>
        <div className="space-y-3">
          <label className="flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-muted/50">
            <div>
              <div className="text-sm font-medium">Save command history</div>
              <div className="text-xs text-muted-foreground">Store command history locally</div>
            </div>
            <input
              type="checkbox"
              checked={settings.saveCommandHistory}
              onChange={(e) => updateSetting('saveCommandHistory', e.target.checked)}
              className="h-4 w-4"
            />
          </label>
        </div>
      </div>
    </div>
  );
}
