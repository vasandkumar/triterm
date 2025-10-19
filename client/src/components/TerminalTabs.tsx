import { memo } from 'react';
import { X } from 'lucide-react';
import { Button } from './ui/button';

export interface TerminalTab {
  id: string;
  name?: string;
  shell: string;
  createdAt: number;
}

interface TerminalTabsProps {
  terminals: TerminalTab[];
  activeTerminalIds: string[];
  onTabClick: (terminalId: string) => void;
  onTabClose: (terminalId: string) => void;
}

export const TerminalTabs = memo(function TerminalTabs({
  terminals,
  activeTerminalIds,
  onTabClick,
  onTabClose,
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
    <nav className="flex items-center gap-1 px-4 py-2 bg-muted/30 border-b overflow-x-auto" role="tablist" aria-label="Terminal tabs">
      {terminals.map((terminal, index) => {
        const isActive = activeTerminalIds.includes(terminal.id);
        const tabName = getTabName(terminal, index);

        return (
          <div
            key={terminal.id}
            className={`
              group relative flex items-center gap-2 px-3 py-1.5 rounded-t-md
              transition-all duration-150 cursor-pointer min-w-[120px] max-w-[200px]
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
            <span className="text-sm font-medium truncate flex-1">
              {tabName}
            </span>

            {/* Close Button */}
            <Button
              variant="ghost"
              size="icon"
              className={`
                h-5 w-5 rounded-sm opacity-0 group-hover:opacity-100
                transition-opacity hover:bg-destructive/10 hover:text-destructive
                ${isActive ? 'opacity-70' : ''}
              `}
              aria-label={`Close ${tabName}`}
              onClick={(e) => {
                e.stopPropagation();
                onTabClose(terminal.id);
              }}
            >
              <X className="h-3 w-3" aria-hidden="true" />
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
        <div className="text-sm text-muted-foreground py-1">
          No terminals open. Click "New Terminal" to get started.
        </div>
      )}
    </nav>
  );
});
