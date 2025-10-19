import { useState, useCallback, useEffect, lazy, Suspense } from 'react';
import { useSocket } from './hooks/useSocket';
import { useAuth } from './contexts/AuthContext';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { useCommandHistory } from './hooks/useCommandHistory';
import { TerminalTabs } from './components/TerminalTabs';
import { AuthPage } from './components/Auth/AuthPage';
import { PWAUpdatePrompt } from './components/PWAUpdatePrompt';
import { Button } from './components/ui/button';
import { Separator } from './components/ui/separator';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './components/ui/tooltip';
import { Terminal as TerminalIcon, Plus, Settings, Info, Wifi, WifiOff, LogOut, User, LayoutGrid, PanelLeftDashed, Shield } from 'lucide-react';
import type { User as UserType } from './lib/authApi';
import { saveTokens } from './lib/tokenStorage';
import { getCurrentUser } from './lib/authApi';
import { AdminDashboard } from './pages/Admin/AdminDashboard';

// Lazy load heavy components for better performance
const ResizableTerminalLayout = lazy(() => import('./components/ResizableTerminalLayout').then(m => ({ default: m.ResizableTerminalLayout })));
const DraggableTerminalGrid = lazy(() => import('./components/DraggableTerminalGrid').then(m => ({ default: m.DraggableTerminalGrid })));
const SettingsDialog = lazy(() => import('./components/SettingsDialog').then(m => ({ default: m.SettingsDialog })));
const AboutDialog = lazy(() => import('./components/AboutDialog').then(m => ({ default: m.AboutDialog })));
const CommandHistoryDialog = lazy(() => import('./components/CommandHistoryDialog').then(m => ({ default: m.CommandHistoryDialog })));

interface TerminalTab {
  id: string;
  name?: string;
  shell: string;
  createdAt: number;
}

interface CreateTerminalResponse {
  success?: boolean;
  terminalId?: string;
  shell?: string;
  error?: string;
}

// OAuth Callback Handler Component
function OAuthCallbackHandler() {
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [errorMessage, setErrorMessage] = useState<string>('');

  useEffect(() => {
    async function handleOAuthCallback() {
      try {
        // Get tokens from URL
        const urlParams = new URLSearchParams(window.location.search);
        const accessToken = urlParams.get('accessToken');
        const refreshToken = urlParams.get('refreshToken');
        const error = urlParams.get('error');

        if (error) {
          setStatus('error');
          setErrorMessage('OAuth authentication failed. Please try again.');
          setTimeout(() => {
            window.location.href = '/';
          }, 3000);
          return;
        }

        if (!accessToken || !refreshToken) {
          setStatus('error');
          setErrorMessage('Invalid OAuth response. Missing tokens.');
          setTimeout(() => {
            window.location.href = '/';
          }, 3000);
          return;
        }

        // Save tokens
        saveTokens({ accessToken, refreshToken });

        // Verify authentication by fetching user
        await getCurrentUser();

        setStatus('success');

        // Redirect to home
        setTimeout(() => {
          window.location.href = '/';
        }, 1000);
      } catch (error) {
        console.error('OAuth callback error:', error);
        setStatus('error');
        setErrorMessage('Failed to complete authentication. Please try again.');
        setTimeout(() => {
          window.location.href = '/';
        }, 3000);
      }
    }

    handleOAuthCallback();
  }, []);

  return (
    <div className="h-screen w-screen flex items-center justify-center bg-gray-900">
      <div className="text-center max-w-md">
        {status === 'processing' && (
          <>
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Completing authentication...</p>
          </>
        )}
        {status === 'success' && (
          <>
            <div className="rounded-full h-12 w-12 bg-green-500/20 flex items-center justify-center mx-auto mb-4">
              <svg
                className="h-6 w-6 text-green-500"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <p className="text-green-400">Authentication successful!</p>
            <p className="text-gray-400 text-sm mt-2">Redirecting to TriTerm...</p>
          </>
        )}
        {status === 'error' && (
          <>
            <div className="rounded-full h-12 w-12 bg-red-500/20 flex items-center justify-center mx-auto mb-4">
              <svg
                className="h-6 w-6 text-red-500"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </div>
            <p className="text-red-400">{errorMessage}</p>
            <p className="text-gray-400 text-sm mt-2">Redirecting to login...</p>
          </>
        )}
      </div>
    </div>
  );
}

function App() {
  const { isAuthenticated, user, logout, loading: authLoading } = useAuth();

  // Check if this is the OAuth callback route
  if (window.location.pathname === '/oauth-callback') {
    return <OAuthCallbackHandler />;
  }

  // Check if this is the admin route
  if (window.location.pathname === '/admin' || window.location.pathname.startsWith('/admin/')) {
    // Show auth page if not authenticated
    if (!isAuthenticated && !authLoading) {
      return <AuthPage />;
    }

    // Show loading state while checking auth
    if (authLoading) {
      return (
        <div className="h-screen w-screen flex items-center justify-center bg-gray-900">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Loading...</p>
          </div>
        </div>
      );
    }

    // Render admin dashboard
    return <AdminDashboard />;
  }

  // Show auth page if not authenticated
  if (!isAuthenticated && !authLoading) {
    return <AuthPage />;
  }

  // Show loading state while checking auth
  if (authLoading) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-gray-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-400">Loading...</p>
        </div>
      </div>
    );
  }

  // Only connect socket after authentication
  return <AuthenticatedApp user={user} logout={logout} />;
}

function AuthenticatedApp({ user, logout }: { user: UserType | null; logout: () => void }) {
  const { socket, isConnected, error } = useSocket();
  const [terminals, setTerminals] = useState<TerminalTab[]>([]);
  const [activeTerminalIds, setActiveTerminalIds] = useState<string[]>([]);
  const [layoutMode, setLayoutMode] = useState<'grid' | 'auto'>('grid');
  const [isCreating, setIsCreating] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  // Command history
  const { history, addCommand, clearHistory, removeEntry } = useCommandHistory();

  // Create new terminal
  const createTerminal = useCallback(() => {
    if (!socket || !isConnected || isCreating) return;

    setIsCreating(true);

    socket.emit(
      'create-terminal',
      {
        cols: 80,
        rows: 24,
      },
      (response: CreateTerminalResponse) => {
        setIsCreating(false);

        if (response.error) {
          console.error('Failed to create terminal:', response.error);
          alert(`Failed to create terminal: ${response.error}`);
          return;
        }

        if (response.success && response.terminalId && response.shell) {
          const newTerminal = {
            id: response.terminalId,
            shell: response.shell,
            createdAt: Date.now(),
          };
          setTerminals((prev) => [...prev, newTerminal]);
          setActiveTerminalIds((prev) => [...prev, response.terminalId]); // Add new terminal to active set
        }
      }
    );
  }, [socket, isConnected, isCreating]);

  // Toggle terminal visibility
  const toggleTerminal = useCallback((terminalId: string) => {
    setActiveTerminalIds((prev) => {
      if (prev.includes(terminalId)) {
        // If already active, remove it (but keep at least one active if possible)
        const newActive = prev.filter((id) => id !== terminalId);
        return newActive.length > 0 ? newActive : prev;
      } else {
        // If not active, add it to the active set
        return [...prev, terminalId];
      }
    });
  }, []);

  // Rename terminal
  const renameTerminal = useCallback((terminalId: string, newName: string) => {
    setTerminals((prev) =>
      prev.map((t) => (t.id === terminalId ? { ...t, name: newName } : t))
    );
  }, []);

  // Close terminal
  const closeTerminal = useCallback(
    (terminalId: string) => {
      if (!socket) return;

      socket.emit('close-terminal', { terminalId });

      setTerminals((prev) => prev.filter((t) => t.id !== terminalId));
      setActiveTerminalIds((prev) => prev.filter((id) => id !== terminalId));
    },
    [socket]
  );

  // Navigate to next active terminal
  const nextTerminal = useCallback(() => {
    if (activeTerminalIds.length === 0) return;

    // Find the current "primary" terminal (first in the list)
    const currentIndex = terminals.findIndex((t) => t.id === activeTerminalIds[0]);
    const nextIndex = (currentIndex + 1) % terminals.length;
    const nextTerminal = terminals[nextIndex];

    if (nextTerminal) {
      setActiveTerminalIds([nextTerminal.id]);
    }
  }, [terminals, activeTerminalIds]);

  // Navigate to previous active terminal
  const previousTerminal = useCallback(() => {
    if (activeTerminalIds.length === 0) return;

    const currentIndex = terminals.findIndex((t) => t.id === activeTerminalIds[0]);
    const previousIndex = currentIndex === 0 ? terminals.length - 1 : currentIndex - 1;
    const previousTerminal = terminals[previousIndex];

    if (previousTerminal) {
      setActiveTerminalIds([previousTerminal.id]);
    }
  }, [terminals, activeTerminalIds]);

  // Close the first active terminal
  const closeActiveTerminal = useCallback(() => {
    if (activeTerminalIds.length > 0) {
      closeTerminal(activeTerminalIds[0]);
    }
  }, [activeTerminalIds, closeTerminal]);

  // Keyboard shortcuts
  useKeyboardShortcuts({
    onNewTerminal: createTerminal,
    onCloseTerminal: closeActiveTerminal,
    onNextTerminal: nextTerminal,
    onPreviousTerminal: previousTerminal,
    onToggleSettings: () => setSettingsOpen((prev) => !prev),
    onSearchHistory: () => setHistoryOpen(true),
  });

  // Create initial terminal on connect
  useEffect(() => {
    if (isConnected && terminals.length === 0 && !isCreating) {
      // Small delay to ensure socket is fully ready
      const timer = setTimeout(() => {
        createTerminal();
      }, 100);

      return () => clearTimeout(timer);
    }
  }, [isConnected, terminals.length, isCreating, createTerminal]);

  return (
    <TooltipProvider>
      <div className="flex flex-col h-screen bg-background text-foreground">
        {/* Header */}
        <header className="flex items-center justify-between px-4 py-3 bg-card border-b shadow-sm" role="banner" aria-label="Application header">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="p-2 bg-primary/10 rounded-lg">
                <TerminalIcon className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h1 className="text-lg font-bold">TriTerm</h1>
                <p className="text-xs text-muted-foreground">Enterprise Terminal Manager</p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Connection Status */}
            <Tooltip>
              <TooltipTrigger asChild>
                <div
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm ${
                    isConnected
                      ? 'bg-green-500/10 text-green-600 dark:text-green-400'
                      : 'bg-red-500/10 text-red-600 dark:text-red-400'
                  }`}
                  role="status"
                  aria-live="polite"
                  aria-label={isConnected ? 'Connected to server' : 'Disconnected from server'}
                >
                  {isConnected ? <Wifi className="h-4 w-4" aria-hidden="true" /> : <WifiOff className="h-4 w-4" aria-hidden="true" />}
                  <span className="font-medium">{isConnected ? 'Connected' : 'Disconnected'}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {isConnected ? 'Connected to server' : error || 'Disconnected from server'}
              </TooltipContent>
            </Tooltip>

            {/* Terminal Count */}
            <div
              className="px-3 py-1.5 bg-muted rounded-md text-sm font-medium"
              role="status"
              aria-label={`${terminals.length} terminal${terminals.length !== 1 ? 's' : ''} open`}
            >
              {terminals.length} Terminal{terminals.length !== 1 ? 's' : ''}
            </div>

            <Separator orientation="vertical" className="h-6" />

            {/* New Terminal Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  onClick={createTerminal}
                  disabled={!isConnected || isCreating}
                  size="sm"
                  className="gap-2"
                  aria-label="Create new terminal"
                >
                  <Plus className="h-4 w-4" aria-hidden="true" />
                  New Terminal
                </Button>
              </TooltipTrigger>
              <TooltipContent>Create a new terminal instance (Max 10)</TooltipContent>
            </Tooltip>

            {/* Layout Mode Toggle */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant={layoutMode === 'grid' ? 'default' : 'ghost'}
                  size="icon"
                  onClick={() => setLayoutMode(layoutMode === 'grid' ? 'auto' : 'grid')}
                  aria-label={layoutMode === 'grid' ? 'Switch to auto layout' : 'Switch to grid layout'}
                >
                  {layoutMode === 'grid' ? <LayoutGrid className="h-4 w-4" aria-hidden="true" /> : <PanelLeftDashed className="h-4 w-4" aria-hidden="true" />}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {layoutMode === 'grid' ? 'Switch to Auto Layout' : 'Switch to Grid Layout (Drag & Drop)'}
              </TooltipContent>
            </Tooltip>

            {/* Settings Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" onClick={() => setSettingsOpen(true)} aria-label="Open settings">
                  <Settings className="h-4 w-4" aria-hidden="true" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Settings</TooltipContent>
            </Tooltip>

            {/* User Menu */}
            <Separator orientation="vertical" className="h-6" />

            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-2 px-3 py-1.5 bg-muted rounded-md text-sm">
                  <User className="h-4 w-4" />
                  <span className="font-medium">{user?.username}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>{user?.email}</TooltipContent>
            </Tooltip>

            {/* Admin Panel Link */}
            {user?.role === 'ADMIN' && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => window.location.href = '/admin'}
                    aria-label="Admin Panel"
                  >
                    <Shield className="h-4 w-4" aria-hidden="true" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Admin Panel</TooltipContent>
              </Tooltip>
            )}

            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" onClick={logout} aria-label="Logout">
                  <LogOut className="h-4 w-4" aria-hidden="true" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Logout</TooltipContent>
            </Tooltip>

            {/* Info Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" onClick={() => setAboutOpen(true)} aria-label="About TriTerm">
                  <Info className="h-4 w-4" aria-hidden="true" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>About TriTerm</TooltipContent>
            </Tooltip>
          </div>
        </header>

        {/* Main Content */}
        <main className="flex-1 overflow-hidden flex flex-col" role="main" aria-label="Terminal workspace">
          {error && !isConnected && (
            <div className="flex items-center justify-center h-full" role="alert" aria-live="assertive">
              <div className="text-center max-w-md">
                <div className="inline-flex p-4 bg-destructive/10 rounded-full mb-4">
                  <WifiOff className="h-12 w-12 text-destructive" aria-hidden="true" />
                </div>
                <h2 className="text-2xl font-bold mb-2">Connection Error</h2>
                <p className="text-muted-foreground mb-4">
                  {error}
                </p>
                {error.includes('not running') && (
                  <div className="bg-muted/50 p-4 rounded-md border border-border mb-4">
                    <p className="text-sm font-medium mb-2">Quick Fix:</p>
                    <ol className="text-sm text-left space-y-2 list-decimal list-inside">
                      <li>Open a new terminal window</li>
                      <li>Navigate to the project directory</li>
                      <li>Run: <code className="bg-background px-2 py-1 rounded border">npm run dev:server</code></li>
                    </ol>
                  </div>
                )}
                <Button
                  onClick={() => window.location.reload()}
                  variant="default"
                  className="mt-4"
                >
                  Retry Connection
                </Button>
              </div>
            </div>
          )}

          {!error && isConnected && (
            <>
              {/* Terminal Tabs */}
              <TerminalTabs
                terminals={terminals}
                activeTerminalIds={activeTerminalIds}
                onTabClick={toggleTerminal}
                onTabClose={closeTerminal}
              />

              {/* Active Terminals - Layout Mode */}
              <div className="flex-1 overflow-hidden">
                {activeTerminalIds.length > 0 && socket ? (
                  <Suspense
                    fallback={
                      <div className="flex items-center justify-center h-full">
                        <div className="text-center">
                          <div className="inline-flex p-4 bg-primary/10 rounded-full mb-4 animate-pulse">
                            <TerminalIcon className="h-12 w-12 text-primary" />
                          </div>
                          <p className="text-muted-foreground">Loading terminal...</p>
                        </div>
                      </div>
                    }
                  >
                    {layoutMode === 'grid' ? (
                      <DraggableTerminalGrid
                        terminalIds={activeTerminalIds}
                        socket={socket}
                        onClose={closeTerminal}
                        onRename={renameTerminal}
                        onCommand={addCommand}
                      />
                    ) : (
                      <ResizableTerminalLayout
                        terminalIds={activeTerminalIds}
                        socket={socket}
                        onClose={closeTerminal}
                        onRename={renameTerminal}
                        onCommand={addCommand}
                      />
                    )}
                  </Suspense>
                ) : (
                  <div className="flex items-center justify-center h-full">
                    <div className="text-center">
                      <p className="text-muted-foreground text-lg">No terminal selected</p>
                      <p className="text-muted-foreground text-sm mt-2">
                        Click on a tab to view it, or create a new terminal
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}

          {!error && !isConnected && (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <div className="inline-flex p-4 bg-primary/10 rounded-full mb-4 animate-pulse">
                  <Wifi className="h-12 w-12 text-primary" />
                </div>
                <h2 className="text-2xl font-bold mb-2">Connecting...</h2>
                <p className="text-muted-foreground">Establishing connection to the server</p>
              </div>
            </div>
          )}
        </main>

        {/* Footer */}
        <footer className="px-4 py-2 bg-card border-t text-xs text-muted-foreground flex items-center justify-between" role="contentinfo" aria-label="Application footer">
          <div className="flex items-center gap-4">
            <span>TriTerm v1.0.0</span>
            <Separator orientation="vertical" className="h-3" />
            <span>Server: {isConnected ? 'localhost:3000' : 'Not connected'}</span>
          </div>
          <div>Built with React, Socket.io & xterm.js</div>
        </footer>

        {/* Dialogs - Lazy loaded for better performance */}
        <Suspense fallback={null}>
          {settingsOpen && <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />}
          {aboutOpen && <AboutDialog open={aboutOpen} onOpenChange={setAboutOpen} />}
          {historyOpen && (
            <CommandHistoryDialog
              open={historyOpen}
              onOpenChange={setHistoryOpen}
              history={history}
              onClearHistory={clearHistory}
              onRemoveEntry={removeEntry}
            />
          )}
        </Suspense>

        {/* PWA Update Prompt */}
        <PWAUpdatePrompt />
      </div>
    </TooltipProvider>
  );
}

export default App;
