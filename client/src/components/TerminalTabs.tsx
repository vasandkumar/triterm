import { memo } from 'react';
import { X, Smartphone, Share2, Users } from 'lucide-react';
import { Button } from './ui/button';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip';

export interface TerminalTab {
  id: string;
  name?: string;
  shell: string;
  createdAt: number;
  shareCode?: string;
  pendingRequestCount?: number;
  deviceCount?: number;
  devices?: Array<{
    deviceId?: string;
    deviceName?: string;
    connectedAt?: Date;
  }>;
  isConnectedOnThisDevice?: boolean;
}

interface TerminalTabsProps {
  terminals: TerminalTab[];
  activeTerminalIds: string[];
  onTabClick: (terminalId: string) => void;
  onTabClose: (terminalId: string) => void;
  onShare?: (terminalId: string) => void;
  onManageSharing?: (terminalId: string) => void;
}

export const TerminalTabs = memo(function TerminalTabs({
  terminals,
  activeTerminalIds,
  onTabClick,
  onTabClose,
  onShare,
  onManageSharing,
}: TerminalTabsProps) {
  // Generate default tab name
  const getTabName = (terminal: TerminalTab, index: number) => {
    if (terminal.name) {
      return terminal.name;
    }
    // Extract shell name (e.g., "/bin/bash" -> "bash")
    const shellName = terminal.shell.split('/').pop() || 'terminal';
    return `${shellName} #${index + 1}`;
  };

  return (
    <nav className="flex items-center gap-0.5 px-3 py-1 bg-muted/30 border-b overflow-x-auto" role="tablist" aria-label="Terminal tabs">
      {terminals.map((terminal, index) => {
        const isActive = activeTerminalIds.includes(terminal.id);
        const tabName = getTabName(terminal, index);

        return (
          <div
            key={terminal.id}
            className={`
              group relative flex items-center gap-1.5 px-2.5 py-1 rounded-t-md
              transition-all duration-150 cursor-pointer min-w-[100px] max-w-[180px]
              ${
                isActive
                  ? 'bg-background text-foreground shadow-sm border-t border-x'
                  : 'bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground'
              }
            `}
            role="tab"
            aria-selected={isActive}
            aria-label={tabName}
            tabIndex={0}
            onClick={() => onTabClick(terminal.id)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onTabClick(terminal.id);
              }
            }}
          >
            {/* Tab Label */}
            <span className="text-xs font-medium truncate flex-1">
              {tabName}
            </span>

            {/* Multi-Device Indicator */}
            {terminal.deviceCount && terminal.deviceCount > 1 && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="flex items-center gap-0.5 px-1 py-0.5 bg-primary/10 text-primary rounded text-[10px] font-medium">
                      <Smartphone className="h-2.5 w-2.5" />
                      <span>{terminal.deviceCount}</span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="max-w-xs">
                    <div className="space-y-1">
                      <p className="font-semibold text-sm">Connected Devices ({terminal.deviceCount})</p>
                      {terminal.devices && terminal.devices.length > 0 ? (
                        <ul className="text-xs space-y-0.5">
                          {terminal.devices.map((device, idx) => (
                            <li key={idx} className="flex items-center gap-1.5">
                              <Smartphone className="h-3 w-3" />
                              <span>{device.deviceName || device.deviceId || `Device ${idx + 1}`}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-xs">Synced across {terminal.deviceCount} devices</p>
                      )}
                    </div>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}

            {/* Share Button */}
            {onShare && !terminal.shareCode && (
              <Button
                variant="ghost"
                size="icon"
                className={`
                  h-4 w-4 rounded-sm opacity-0 group-hover:opacity-100
                  transition-opacity hover:bg-primary/10 hover:text-primary
                  ${isActive ? 'opacity-70' : ''}
                `}
                aria-label={`Share ${tabName}`}
                onClick={(e) => {
                  e.stopPropagation();
                  onShare(terminal.id);
                }}
              >
                <Share2 className="h-2.5 w-2.5" aria-hidden="true" />
              </Button>
            )}

            {/* Manage Sharing Button */}
            {onManageSharing && terminal.shareCode && (
              <div className="relative">
                <Button
                  variant="ghost"
                  size="icon"
                  className={`
                    h-4 w-4 rounded-sm opacity-0 group-hover:opacity-100
                    transition-opacity hover:bg-primary/10 hover:text-primary
                    ${isActive ? 'opacity-70' : ''}
                    ${terminal.pendingRequestCount && terminal.pendingRequestCount > 0 ? '!opacity-100' : ''}
                  `}
                  aria-label={`Manage sharing for ${tabName}${terminal.pendingRequestCount && terminal.pendingRequestCount > 0 ? ` (${terminal.pendingRequestCount} pending)` : ''}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    onManageSharing(terminal.id);
                  }}
                >
                  <Users className="h-2.5 w-2.5" aria-hidden="true" />
                </Button>
                {terminal.pendingRequestCount && terminal.pendingRequestCount > 0 && (
                  <span className="absolute -top-0.5 -right-0.5 flex h-3 w-3 items-center justify-center rounded-full bg-red-500 text-[8px] font-bold text-white ring-1 ring-background">
                    {terminal.pendingRequestCount > 9 ? '9+' : terminal.pendingRequestCount}
                  </span>
                )}
              </div>
            )}

            {/* Close Button */}
            <Button
              variant="ghost"
              size="icon"
              className={`
                h-4 w-4 rounded-sm opacity-0 group-hover:opacity-100
                transition-opacity hover:bg-destructive/10 hover:text-destructive
                ${isActive ? 'opacity-70' : ''}
              `}
              aria-label={`Close ${tabName}`}
              onClick={(e) => {
                e.stopPropagation();
                onTabClose(terminal.id);
              }}
            >
              <X className="h-2.5 w-2.5" aria-hidden="true" />
            </Button>

            {/* Active indicator */}
            {isActive && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary" />
            )}
          </div>
        );
      })}

      {/* Empty state message */}
      {terminals.length === 0 && (
        <div className="text-xs text-muted-foreground py-0.5">
          No terminals open. Click "New Terminal" to get started.
        </div>
      )}
    </nav>
  );
});
