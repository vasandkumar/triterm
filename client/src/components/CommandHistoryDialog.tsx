import { useState, useMemo } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from './ui/dialog';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { Separator } from './ui/separator';
import { Search, Trash2, Copy, Terminal as TerminalIcon, Clock } from 'lucide-react';
import { CommandHistoryEntry } from '../hooks/useCommandHistory';

interface CommandHistoryDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  history: CommandHistoryEntry[];
  onClearHistory: () => void;
  onRemoveEntry: (id: string) => void;
}

export function CommandHistoryDialog({
  open,
  onOpenChange,
  history,
  onClearHistory,
  onRemoveEntry,
}: CommandHistoryDialogProps) {
  const [searchQuery, setSearchQuery] = useState('');

  // Filter history based on search query
  const filteredHistory = useMemo(() => {
    if (!searchQuery.trim()) {
      return history;
    }
    const lowerQuery = searchQuery.toLowerCase();
    return history.filter((entry) => entry.command.toLowerCase().includes(lowerQuery));
  }, [history, searchQuery]);

  const handleCopy = (command: string) => {
    navigator.clipboard.writeText(command);
  };

  const formatTimestamp = (timestamp: number) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;

    return date.toLocaleDateString();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <TerminalIcon className="h-5 w-5" />
            Command History
          </DialogTitle>
          <DialogDescription>
            Search and manage your command history across all terminals
          </DialogDescription>
        </DialogHeader>

        {/* Search Input */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search commands..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
            autoFocus
          />
        </div>

        <Separator />

        {/* History List */}
        <div className="flex-1 overflow-y-auto min-h-[300px] max-h-[400px]">
          {filteredHistory.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
              <TerminalIcon className="h-12 w-12 mb-3 opacity-50" />
              <p className="text-sm">
                {searchQuery ? 'No commands found' : 'No command history yet'}
              </p>
              <p className="text-xs mt-1">
                {searchQuery ? 'Try a different search term' : 'Commands will appear here as you type'}
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredHistory.map((entry) => (
                <div
                  key={entry.id}
                  className="group flex items-center gap-3 p-3 rounded-lg border hover:bg-muted/50 transition-colors"
                >
                  {/* Timestamp */}
                  <div className="flex items-center gap-1 text-xs text-muted-foreground min-w-[80px]">
                    <Clock className="h-3 w-3" />
                    {formatTimestamp(entry.timestamp)}
                  </div>

                  {/* Command */}
                  <code className="flex-1 text-sm font-mono bg-muted/50 px-3 py-1.5 rounded truncate">
                    {entry.command}
                  </code>

                  {/* Actions */}
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => handleCopy(entry.command)}
                      title="Copy command"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 hover:bg-destructive/10 hover:text-destructive"
                      onClick={() => onRemoveEntry(entry.id)}
                      title="Remove from history"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <DialogFooter className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            {filteredHistory.length} {filteredHistory.length === 1 ? 'command' : 'commands'}
            {searchQuery && ` matching "${searchQuery}"`}
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={onClearHistory}
              className="text-destructive"
              disabled={history.length === 0}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Clear All
            </Button>
            <Button onClick={() => onOpenChange(false)}>Close</Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
