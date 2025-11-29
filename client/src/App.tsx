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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { Terminal as TerminalIcon, Plus, Settings, Info, Wifi, WifiOff, LogOut, User, LayoutGrid, PanelLeftDashed, Shield, ChevronUp, ChevronDown } from 'lucide-react';
import type { User as UserType } from './lib/authApi';
import { getCurrentUser } from './lib/authApi';
import { AdminDashboard } from './pages/Admin/AdminDashboard';

// Lazy load heavy components for better performance
const ResizableTerminalLayout = lazy(() => import('./components/ResizableTerminalLayout').then(m => ({ default: m.ResizableTerminalLayout })));
const DraggableTerminalGrid = lazy(() => import('./components/DraggableTerminalGrid').then(m => ({ default: m.DraggableTerminalGrid })));
const SettingsDialog = lazy(() => import('./components/SettingsDialog').then(m => ({ default: m.SettingsDialog })));
const AboutDialog = lazy(() => import('./components/AboutDialog').then(m => ({ default: m.AboutDialog })));
const CommandHistoryDialog = lazy(() => import('./components/CommandHistoryDialog').then(m => ({ default: m.CommandHistoryDialog })));
const CreateShareLinkDialog = lazy(() => import('./components/CreateShareLinkDialog').then(m => ({ default: m.CreateShareLinkDialog })));
const JoinSharedTerminal = lazy(() => import('./components/JoinSharedTerminal').then(m => ({ default: m.JoinSharedTerminal })));
const ShareApprovalPopup = lazy(() => import('./components/ShareApprovalPopup').then(m => ({ default: m.ShareApprovalPopup })));
const ShareManagementDialog = lazy(() => import('./components/ShareManagementDialog').then(m => ({ default: m.ShareManagementDialog })));
const SharedTerminalViewer = lazy(() => import('./components/SharedTerminalViewer').then(m => ({ default: m.SharedTerminalViewer })));

interface TerminalTab {
  id: string;
  name?: string;
  shell: string;
  createdAt: number;
  sessionId?: string; // Database session ID for sharing
  shareCode?: string; // Active share code for this terminal
  pendingRequestCount?: number; // Number of pending share requests
  initialBuffer?: string; // Buffer to restore on reconnection
  deviceCount?: number; // Number of connected devices
  devices?: Array<{
    deviceId?: string;
    deviceName?: string;
    connectedAt?: Date;
  }>;
  isConnectedOnThisDevice?: boolean; // Is this terminal connected on this device
}

interface CreateTerminalResponse {
  success?: boolean;
  terminalId?: string;
  shell?: string;
  sessionId?: string;
  error?: string;
}

// OAuth Callback Handler Component
function OAuthCallbackHandler() {
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [errorMessage, setErrorMessage] = useState<string>('');

  useEffect(() => {
    async function handleOAuthCallback() {
      try {
        // Check for error in URL
        const urlParams = new URLSearchParams(window.location.search);
        const error = urlParams.get('error');
        const pendingApproval = urlParams.get('pendingApproval');

        if (error) {
          setStatus('error');
          setErrorMessage('OAuth authentication failed. Please try again.');
          setTimeout(() => {
            window.location.href = '/';
          }, 3000);
          return;
        }

        if (pendingApproval) {
          setStatus('error');
          setErrorMessage('Account created successfully. Your account is pending admin approval.');
          setTimeout(() => {
            window.location.href = '/';
          }, 3000);
          return;
        }

        // Tokens are now in httpOnly cookies (set by backend)
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

  // Check if this is a share link route (public, no auth required)
  if (window.location.pathname.startsWith('/share/')) {
    const pathParts = window.location.pathname.split('/share/')[1].split('/');
    const shareCode = pathParts[0];
    const isTerminalView = pathParts[1] === 'terminal';

    return (
      <Suspense fallback={
        <div className="h-screen w-screen flex items-center justify-center bg-gray-900">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Loading...</p>
          </div>
        </div>
      }>
        {isTerminalView ? (
          <SharedTerminalViewer shareCode={shareCode} />
        ) : (
          <JoinSharedTerminal shareCode={shareCode} />
        )}
      </Suspense>
    );
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
  const [layoutMode, setLayoutMode] = useState<'grid' | 'auto' | 'custom'>(() => {
    return (localStorage.getItem('triterm_layout_mode') as 'grid' | 'auto' | 'custom') || 'grid';
  });
  const [gridColumns, setGridColumns] = useState(() => {
    const saved = localStorage.getItem('triterm_grid_columns');
    return saved ? parseInt(saved) : 2;
  });
  const [customLayout, setCustomLayout] = useState<string>(() => {
    return localStorage.getItem('triterm_custom_layout') || '2,3';
  });
  const [terminalHeight, setTerminalHeight] = useState(() => {
    const saved = localStorage.getItem('triterm_terminal_height');
    return saved ? parseInt(saved) : 400;
  });
  const [isCreating, setIsCreating] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [hasAttemptedReconnect, setHasAttemptedReconnect] = useState(false);
  const [headerCollapsed, setHeaderCollapsed] = useState(() => {
    const saved = localStorage.getItem('triterm_header_collapsed');
    return saved === 'true';
  });

  // External sharing state
  const [shareDialogOpen, setShareDialogOpen] = useState(false);
  const [shareTerminalId, setShareTerminalId] = useState<string | null>(null);
  const [shareSessionId, setShareSessionId] = useState<string | null>(null);

  // Share approval popup state
  const [approvalPopupOpen, setApprovalPopupOpen] = useState(false);
  const [approvalShareCode, setApprovalShareCode] = useState<string | null>(null);

  // Share management dialog state
  const [shareManagementOpen, setShareManagementOpen] = useState(false);
  const [managementShareCode, setManagementShareCode] = useState<string | null>(null);
  const [managementTerminalId, setManagementTerminalId] = useState<string | null>(null);

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
          const newTerminal: TerminalTab = {
            id: response.terminalId,
            shell: response.shell,
            sessionId: response.sessionId, // Store sessionId for sharing
            createdAt: Date.now(),
            deviceCount: 1, // This device just created it
            devices: [],
            isConnectedOnThisDevice: true,
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

  // Handle share terminal
  const handleShareTerminal = useCallback((terminalId: string) => {
    // Find the terminal to get its sessionId
    const terminal = terminals.find(t => t.id === terminalId);
    if (!terminal) {
      alert('Terminal not found');
      return;
    }
    if (!terminal.sessionId) {
      alert('Cannot share this terminal: No session ID available');
      return;
    }
    setShareTerminalId(terminalId);
    setShareSessionId(terminal.sessionId);
    setShareDialogOpen(true);
  }, [terminals]);

  // Handle manage sharing
  const handleManageSharing = useCallback((terminalId: string) => {
    const terminal = terminals.find(t => t.id === terminalId);
    if (!terminal) {
      alert('Terminal not found');
      return;
    }
    if (!terminal.shareCode) {
      alert('This terminal does not have an active share link');
      return;
    }
    setManagementTerminalId(terminalId);
    setManagementShareCode(terminal.shareCode);
    setShareManagementOpen(true);

    // Reset pending request count when opening management dialog
    setTerminals((prev) =>
      prev.map((t) =>
        t.id === terminalId ? { ...t, pendingRequestCount: 0 } : t
      )
    );
  }, [terminals]);

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

  // Save terminal IDs to localStorage (only after initial reconnection attempt)
  useEffect(() => {
    // Don't save during initial mount - wait for reconnection to complete
    if (!hasAttemptedReconnect) {
      return;
    }

    const terminalIds = terminals.map((t) => ({ id: t.id, name: t.name, shell: t.shell }));
    localStorage.setItem('triterm_sessions', JSON.stringify(terminalIds));
    console.log('Saved terminal sessions to localStorage:', terminalIds);
  }, [terminals, hasAttemptedReconnect]);

  // Save layout preferences to localStorage
  useEffect(() => {
    localStorage.setItem('triterm_layout_mode', layoutMode);
  }, [layoutMode]);

  useEffect(() => {
    localStorage.setItem('triterm_grid_columns', gridColumns.toString());
  }, [gridColumns]);

  useEffect(() => {
    localStorage.setItem('triterm_custom_layout', customLayout);
  }, [customLayout]);

  useEffect(() => {
    localStorage.setItem('triterm_header_collapsed', headerCollapsed.toString());
  }, [headerCollapsed]);

  // Session synchronization: Fetch all terminals from server
  useEffect(() => {
    if (!isConnected || !socket || isCreating) return;

    // Check if we've already attempted synchronization
    if (hasAttemptedReconnect) return;

    // For authenticated users, fetch terminals from server
    if (user) {
      console.log('[SessionSync] Fetching user terminals from server...');

      socket.emit('list-terminals', (response: any) => {
        if (response.error) {
          console.error('[SessionSync] Failed to fetch terminals:', response.error);

          // Fallback to localStorage-based reconnection
          fallbackToLocalStorageReconnection();
          return;
        }

        if (response.success && Array.isArray(response.terminals)) {
          const serverTerminals = response.terminals;
          console.log(`[SessionSync] Found ${serverTerminals.length} terminal(s) on server`);

          if (serverTerminals.length === 0) {
            // No terminals on server, create initial terminal
            console.log('[SessionSync] No existing terminals, creating new terminal');
            setTimeout(() => {
              createTerminal();
              setHasAttemptedReconnect(true);
            }, 100);
            return;
          }

          // Reconnect to all terminals found on server
          let reconnectedCount = 0;
          let completedCount = 0;
          const totalTerminals = serverTerminals.length;

          serverTerminals.forEach((serverTerminal: any) => {
            const shouldReconnect = !serverTerminal.isConnectedOnThisDevice;

            if (shouldReconnect) {
              // Reconnect to this terminal
              socket.emit('reconnect-terminal', { terminalId: serverTerminal.terminalId }, (response: any) => {
                completedCount++;

                if (response.success && response.terminalId) {
                  reconnectedCount++;
                  console.log(`[SessionSync] Reconnected to terminal ${response.terminalId} (${reconnectedCount}/${totalTerminals})`);

                  const terminal: TerminalTab = {
                    id: response.terminalId,
                    shell: serverTerminal.shell,
                    createdAt: serverTerminal.createdAt || Date.now(),
                    initialBuffer: response.buffer,
                    deviceCount: serverTerminal.deviceCount,
                    devices: serverTerminal.devices,
                    isConnectedOnThisDevice: true,
                  };

                  setTerminals((prev) => {
                    if (prev.some((t) => t.id === response.terminalId)) {
                      return prev;
                    }
                    return [...prev, terminal];
                  });

                  setActiveTerminalIds((prev) => {
                    if (prev.includes(response.terminalId)) {
                      return prev;
                    }
                    return [...prev, response.terminalId];
                  });
                } else {
                  console.warn(`[SessionSync] Failed to reconnect to terminal ${serverTerminal.terminalId}:`, response.error);
                }

                // After all reconnection attempts
                if (completedCount === totalTerminals) {
                  setHasAttemptedReconnect(true);

                  console.log('[SessionSync] Reconnection complete:', {
                    total: totalTerminals,
                    reconnected: reconnectedCount,
                    failed: totalTerminals - reconnectedCount,
                  });

                  if (reconnectedCount === 0) {
                    // All failed, create new terminal
                    console.warn('[SessionSync] All reconnections failed, creating new terminal');
                    setTimeout(() => {
                      createTerminal();
                    }, 100);
                  }
                }
              });
            } else {
              // Terminal already connected on this device
              completedCount++;
              console.log(`[SessionSync] Terminal ${serverTerminal.terminalId} already connected on this device`);

              const terminal: TerminalTab = {
                id: serverTerminal.terminalId,
                shell: serverTerminal.shell,
                createdAt: serverTerminal.createdAt || Date.now(),
                deviceCount: serverTerminal.deviceCount,
                devices: serverTerminal.devices,
                isConnectedOnThisDevice: true,
              };

              setTerminals((prev) => {
                if (prev.some((t) => t.id === serverTerminal.terminalId)) {
                  return prev;
                }
                return [...prev, terminal];
              });

              setActiveTerminalIds((prev) => {
                if (prev.includes(serverTerminal.terminalId)) {
                  return prev;
                }
                return [...prev, serverTerminal.terminalId];
              });

              if (completedCount === totalTerminals) {
                setHasAttemptedReconnect(true);
              }
            }
          });
        } else {
          console.error('[SessionSync] Invalid response from server');
          fallbackToLocalStorageReconnection();
        }
      });
    } else {
      // Non-authenticated users: use localStorage-based reconnection
      fallbackToLocalStorageReconnection();
    }

    // Fallback function for non-authenticated users or if server fetch fails
    function fallbackToLocalStorageReconnection() {
      const savedSessions = localStorage.getItem('triterm_sessions');
      console.log('[SessionSync] Fallback: Using localStorage reconnection');

      if (!savedSessions) {
        setTimeout(() => {
          createTerminal();
          setHasAttemptedReconnect(true);
        }, 100);
        return;
      }

      try {
        const sessions = JSON.parse(savedSessions);
        if (!Array.isArray(sessions) || sessions.length === 0) {
          setTimeout(() => {
            createTerminal();
            setHasAttemptedReconnect(true);
          }, 100);
          return;
        }

        let reconnectedCount = 0;
        let completedCount = 0;

        sessions.forEach((session: { id: string; name?: string; shell: string }) => {
          socket!.emit('reconnect-terminal', { terminalId: session.id }, (response: any) => {
            completedCount++;

            if (response.success && response.terminalId) {
              reconnectedCount++;
              setTerminals((prev) => {
                if (prev.some((t) => t.id === response.terminalId)) {
                  return prev;
                }
                return [...prev, {
                  id: response.terminalId,
                  name: session.name,
                  shell: session.shell,
                  createdAt: Date.now(),
                  initialBuffer: response.buffer,
                }];
              });
              setActiveTerminalIds((prev) => {
                if (prev.includes(response.terminalId)) {
                  return prev;
                }
                return [...prev, response.terminalId];
              });
            }

            if (completedCount === sessions.length) {
              setHasAttemptedReconnect(true);
              if (reconnectedCount === 0) {
                localStorage.removeItem('triterm_sessions');
                setTimeout(() => {
                  createTerminal();
                }, 100);
              }
            }
          });
        });
      } catch (error) {
        console.error('[SessionSync] Error in fallback reconnection:', error);
        localStorage.removeItem('triterm_sessions');
        setTimeout(() => {
          createTerminal();
          setHasAttemptedReconnect(true);
        }, 100);
      }
    }
  }, [isConnected, socket, hasAttemptedReconnect, createTerminal, isCreating, user]);

  // Listen for multi-device events (device connect/disconnect)
  useEffect(() => {
    if (!socket) return;

    // When another device connects to a terminal
    const handleDeviceConnected = (data: {
      terminalId: string;
      deviceId?: string;
      deviceName?: string;
      deviceCount: number;
      devices: Array<{ deviceId?: string; deviceName?: string }>;
    }) => {
      console.log('[MultiDevice] Device connected to terminal:', data);

      setTerminals((prev) =>
        prev.map((t) =>
          t.id === data.terminalId
            ? {
                ...t,
                deviceCount: data.deviceCount,
                devices: data.devices.map(d => ({
                  ...d,
                  connectedAt: new Date(),
                })),
              }
            : t
        )
      );
    };

    // When another device disconnects from a terminal
    const handleDeviceDisconnected = (data: {
      terminalId: string;
      deviceId?: string;
      deviceName?: string;
      deviceCount: number;
      devices: Array<{ deviceId?: string; deviceName?: string }>;
    }) => {
      console.log('[MultiDevice] Device disconnected from terminal:', data);

      setTerminals((prev) =>
        prev.map((t) =>
          t.id === data.terminalId
            ? {
                ...t,
                deviceCount: data.deviceCount,
                devices: data.devices.map(d => ({
                  ...d,
                  connectedAt: new Date(),
                })),
              }
            : t
        )
      );
    };

    // Listen for multi-device events
    socket.on('terminal-device-connected', handleDeviceConnected);
    socket.on('terminal-device-disconnected', handleDeviceDisconnected);

    // Listen for share request notifications
    const handleNewShareRequest = (data: { shareCode: string; connection: any }) => {
      setApprovalShareCode(data.shareCode);
      setApprovalPopupOpen(true);

      // Increment pending request count for the terminal with this shareCode
      setTerminals((prev) =>
        prev.map((t) =>
          t.shareCode === data.shareCode
            ? { ...t, pendingRequestCount: (t.pendingRequestCount || 0) + 1 }
            : t
        )
      );
    };

    socket.on('share:new-request', handleNewShareRequest);

    // Handle share link deactivation
    const handleShareLinkDeactivated = (data: { terminalId: string; shareCode: string }) => {
      setTerminals((prev) =>
        prev.map((t) =>
          t.id === data.terminalId
            ? { ...t, shareCode: undefined, pendingRequestCount: 0 }
            : t
        )
      );
    };

    socket.on('share:link-deactivated-owner', handleShareLinkDeactivated);

    // Cleanup listeners
    return () => {
      socket.off('terminal-device-connected', handleDeviceConnected);
      socket.off('terminal-device-disconnected', handleDeviceDisconnected);
      socket.off('share:new-request', handleNewShareRequest);
      socket.off('share:link-deactivated-owner', handleShareLinkDeactivated);
    };
  }, [socket]);

  return (
    <TooltipProvider>
      <div className="flex flex-col h-screen bg-background text-foreground">
        {/* Floating Expand Button (only visible when header is collapsed) */}
        {headerCollapsed && (
          <div className="absolute top-2 right-2 z-50">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="default"
                  size="sm"
                  onClick={() => setHeaderCollapsed(false)}
                  aria-label="Expand header"
                  className="shadow-lg"
                >
                  <ChevronDown className="h-4 w-4 mr-2" aria-hidden="true" />
                  Show Header
                </Button>
              </TooltipTrigger>
              <TooltipContent>Expand header</TooltipContent>
            </Tooltip>
          </div>
        )}

        {/* Header */}
        {!headerCollapsed && (
          <header className="flex items-center justify-between px-4 py-3 bg-card border-b shadow-sm transition-all duration-300" role="banner" aria-label="Application header">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="p-2 bg-primary/10 rounded-lg">
                <TerminalIcon className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h1 className="text-lg font-bold">TriTerm</h1>
                <p className="text-xs text-muted-foreground">Web Terminal Manager</p>
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
                  variant="default"
                  size="sm"
                  onClick={() => {
                    const nextMode = layoutMode === 'grid' ? 'auto' : layoutMode === 'auto' ? 'custom' : 'grid';
                    setLayoutMode(nextMode);
                  }}
                  aria-label="Switch layout mode"
                  className="gap-2"
                >
                  {layoutMode === 'grid' && (
                    <>
                      <LayoutGrid className="h-4 w-4" aria-hidden="true" />
                      <span className="hidden sm:inline">Drag Mode</span>
                    </>
                  )}
                  {layoutMode === 'auto' && (
                    <>
                      <PanelLeftDashed className="h-4 w-4" aria-hidden="true" />
                      <span className="hidden sm:inline">Grid Mode</span>
                    </>
                  )}
                  {layoutMode === 'custom' && (
                    <>
                      <LayoutGrid className="h-4 w-4" aria-hidden="true" />
                      <span className="hidden sm:inline">Custom Mode</span>
                    </>
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {layoutMode === 'grid' && 'Drag & Drop Mode - Free positioning'}
                {layoutMode === 'auto' && 'Grid Mode - Even columns'}
                {layoutMode === 'custom' && 'Custom Mode - Different columns per row'}
              </TooltipContent>
            </Tooltip>

            {/* Custom Layout Configuration (only show in custom mode) */}
            {layoutMode === 'custom' && activeTerminalIds.length > 0 && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <div>
                    <Select
                      value={customLayout}
                      onValueChange={setCustomLayout}
                    >
                      <SelectTrigger className="w-[200px] h-9" aria-label="Select custom layout">
                        <div className="flex items-center gap-2">
                          <LayoutGrid className="h-4 w-4 flex-shrink-0" />
                          <SelectValue>
                            {(() => {
                              const layouts: Record<string, string> = {
                                '2,3': '2, then 3',
                                '3,2': '3, then 2',
                                '1,2,3': '1, 2, 3',
                                '2,2,2': '2, 2, 2',
                                '4,3,2,1': '4, 3, 2, 1',
                                '1,3,1': '1, 3, 1'
                              };
                              return (
                                <span className="truncate">{layouts[customLayout] || customLayout}</span>
                              );
                            })()}
                          </SelectValue>
                        </div>
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="2,3">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜⬜ | ⬜⬜⬜</span>
                            <span>2, then 3</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="3,2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜⬜⬜ | ⬜⬜</span>
                            <span>3, then 2</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="1,2,3">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜ | ⬜⬜ | ⬜⬜⬜</span>
                            <span>1, 2, 3</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="2,2,2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜⬜ | ⬜⬜ | ⬜⬜</span>
                            <span>2, 2, 2</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="4,3,2,1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜⬜⬜⬜ | ⬜⬜⬜...</span>
                            <span>4, 3, 2, 1</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="1,3,1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜ | ⬜⬜⬜ | ⬜</span>
                            <span>1, 3, 1</span>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  Define how many terminals per row. Pattern repeats if needed.
                </TooltipContent>
              </Tooltip>
            )}

            {/* Grid Columns Selector (only show in auto layout mode) */}
            {layoutMode === 'auto' && activeTerminalIds.length > 0 && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <div>
                    <Select
                      value={gridColumns.toString()}
                      onValueChange={(value) => setGridColumns(parseInt(value))}
                    >
                      <SelectTrigger className="w-[140px] h-9" aria-label="Select grid columns">
                        <div className="flex items-center gap-2">
                          <LayoutGrid className="h-4 w-4" />
                          <SelectValue />
                        </div>
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜</span>
                            <span>1 Column</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜⬜</span>
                            <span>2 Columns</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="3">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜⬜⬜</span>
                            <span>3 Columns</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="4">
                          <div className="flex items-center gap-2">
                            <span className="text-xs">⬜⬜⬜⬜</span>
                            <span>4 Columns</span>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  Choose how many terminals per row.
                  With {gridColumns} column{gridColumns > 1 ? 's' : ''}, each terminal takes {Math.floor(100/gridColumns)}% width.
                </TooltipContent>
              </Tooltip>
            )}

            {/* Terminal Height Selector (show for auto and custom layout modes) */}
            {(layoutMode === 'auto' || layoutMode === 'custom') && activeTerminalIds.length > 0 && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <div>
                    <Select
                      value={terminalHeight.toString()}
                      onValueChange={(value) => {
                        const height = parseInt(value);
                        setTerminalHeight(height);
                        localStorage.setItem('triterm_terminal_height', height.toString());
                      }}
                    >
                      <SelectTrigger className="w-[180px] h-9" aria-label="Select terminal height">
                        <div className="flex items-center gap-2">
                          <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3-3 3 3M16 15l-3 3-3-3" />
                          </svg>
                          <SelectValue>
                            {(() => {
                              const heights: Record<string, string> = {
                                '300': '300px - Compact',
                                '400': '400px - Default',
                                '500': '500px - Comfortable',
                                '600': '600px - Large',
                                '700': '700px - Extra Large',
                                '800': '800px - Huge',
                                '900': '900px - Maximum'
                              };
                              return (
                                <span className="truncate">{heights[terminalHeight.toString()] || `${terminalHeight}px`}</span>
                              );
                            })()}
                          </SelectValue>
                        </div>
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="300">300px - Compact</SelectItem>
                        <SelectItem value="400">400px - Default</SelectItem>
                        <SelectItem value="500">500px - Comfortable</SelectItem>
                        <SelectItem value="600">600px - Large</SelectItem>
                        <SelectItem value="700">700px - Extra Large</SelectItem>
                        <SelectItem value="800">800px - Huge</SelectItem>
                        <SelectItem value="900">900px - Maximum</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  Adjust the height of each terminal row
                </TooltipContent>
              </Tooltip>
            )}

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

            <Separator orientation="vertical" className="h-6" />

            {/* Collapse Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setHeaderCollapsed(true)}
                  aria-label="Collapse header"
                >
                  <ChevronUp className="h-4 w-4" aria-hidden="true" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Collapse header</TooltipContent>
            </Tooltip>
          </div>
        </header>
        )}

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
                onShare={handleShareTerminal}
                onManageSharing={handleManageSharing}
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
                        terminals={terminals}
                        socket={socket}
                        onClose={closeTerminal}
                        onRename={renameTerminal}
                        onCommand={addCommand}
                      />
                    ) : (
                      <ResizableTerminalLayout
                        terminalIds={activeTerminalIds}
                        terminals={terminals}
                        socket={socket}
                        onClose={closeTerminal}
                        onRename={renameTerminal}
                        onCommand={addCommand}
                        gridColumns={gridColumns}
                        customLayout={customLayout}
                        layoutMode={layoutMode}
                        terminalHeight={terminalHeight}
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
            <span>TriTerm</span>
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
          {shareDialogOpen && shareTerminalId && shareSessionId && (
            <CreateShareLinkDialog
              terminalId={shareTerminalId}
              sessionId={shareSessionId}
              open={shareDialogOpen}
              onClose={() => {
                setShareDialogOpen(false);
                setShareTerminalId(null);
                setShareSessionId(null);
              }}
              onShareCreated={(shareCode) => {
                // Update terminal with shareCode
                setTerminals((prev) =>
                  prev.map((t) =>
                    t.id === shareTerminalId ? { ...t, shareCode } : t
                  )
                );
              }}
            />
          )}
          {approvalPopupOpen && approvalShareCode && (
            <ShareApprovalPopup
              socket={socket}
              shareCode={approvalShareCode}
              terminalId={terminals.find(t => t.id.includes(approvalShareCode))?.id || ''}
              onClose={() => {
                setApprovalPopupOpen(false);
                setApprovalShareCode(null);
              }}
            />
          )}
          {shareManagementOpen && managementShareCode && managementTerminalId && (
            <ShareManagementDialog
              socket={socket}
              terminalId={managementTerminalId}
              shareCode={managementShareCode}
              open={shareManagementOpen}
              onClose={() => {
                setShareManagementOpen(false);
                setManagementShareCode(null);
                setManagementTerminalId(null);
              }}
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
