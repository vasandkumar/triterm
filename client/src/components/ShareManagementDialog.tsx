/**
 * Share Management Dialog
 *
 * Allows terminal owners to:
 * - View pending access requests
 * - View active connections
 * - Approve/reject requests
 * - Kick connected users
 * - Deactivate share links
 */

import { useState, useEffect } from 'react';
import { Socket } from 'socket.io-client';
import { X, Users, Clock, Shield, Trash2, UserX, CheckCircle, XCircle, Eye, Edit3 } from 'lucide-react';
import { Button } from './ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog';
import { Badge } from './ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';

interface ShareLink {
  id: string;
  shareCode: string;
  permission: 'VIEW' | 'CONTROL';
  approvalMode: 'MANUAL' | 'AUTO' | 'PASSWORD_ONLY';
  active: boolean;
  expiresAt: string;
  currentUses: number;
  maxUses: number | null;
  pendingConnections?: PendingConnection[];
  activeConnections?: ActiveConnection[];
}

interface PendingConnection {
  id: string;
  name: string;
  email?: string;
  organization?: string;
  reason?: string;
  requestedAt: string;
  ipAddress: string;
}

interface ActiveConnection {
  id: string;
  name: string;
  email?: string;
  organization?: string;
  connectedAt: string;
  ipAddress: string;
  socketId: string;
}

interface ShareManagementDialogProps {
  socket: Socket | null;
  terminalId: string;
  shareCode: string | null;
  open: boolean;
  onClose: () => void;
}

export function ShareManagementDialog({
  socket,
  terminalId,
  shareCode,
  open,
  onClose,
}: ShareManagementDialogProps) {
  const [shareLink, setShareLink] = useState<ShareLink | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('pending');

  // Fetch share link details
  useEffect(() => {
    if (!open || !shareCode || !socket) return;

    setLoading(true);

    const fetchDetails = () => {
      socket.emit('share:get-details', { shareCode }, (response: any) => {
        if (response.success) {
          setShareLink(response.shareLink);
        }
        setLoading(false);
      });
    };

    fetchDetails();

    // Listen for real-time updates
    const handleUserKicked = (data: { shareCode: string; activeConnectionId: string }) => {
      if (data.shareCode === shareCode) {
        fetchDetails();
      }
    };

    const handleConnectionApproved = (data: { shareCode: string; connectionId: string }) => {
      if (data.shareCode === shareCode) {
        fetchDetails();
      }
    };

    const handleConnectionRejected = (data: { shareCode: string; connectionId: string }) => {
      if (data.shareCode === shareCode) {
        fetchDetails();
      }
    };

    socket.on('share:user-kicked', handleUserKicked);
    socket.on('share:connection-approved-owner', handleConnectionApproved);
    socket.on('share:connection-rejected-owner', handleConnectionRejected);

    return () => {
      socket.off('share:user-kicked', handleUserKicked);
      socket.off('share:connection-approved-owner', handleConnectionApproved);
      socket.off('share:connection-rejected-owner', handleConnectionRejected);
    };
  }, [open, shareCode, socket]);

  // Handle approve request
  const handleApprove = (connectionId: string) => {
    if (!socket) return;

    socket.emit('share:approve-connection', { connectionId }, (response: any) => {
      if (!response.success) {
        alert(`Failed to approve: ${response.error || 'Unknown error'}`);
      }
      // Real-time socket event will handle refresh automatically
    });
  };

  // Handle reject request
  const handleReject = (connectionId: string, reason?: string) => {
    if (!socket) return;

    socket.emit('share:reject-connection', { connectionId, reason }, (response: any) => {
      if (!response.success) {
        alert(`Failed to reject: ${response.error || 'Unknown error'}`);
      }
      // Real-time socket event will handle refresh automatically
    });
  };

  // Handle kick user
  const handleKick = (activeConnectionId: string) => {
    if (!socket) return;

    socket.emit('share:kick-user', { activeConnectionId }, (response: any) => {
      if (!response.success) {
        alert(`Failed to kick user: ${response.error || 'Unknown error'}`);
      }
      // Real-time socket event will handle refresh automatically
    });
  };

  // Handle deactivate share link
  const handleDeactivate = () => {
    if (!socket || !shareCode) return;

    if (!confirm('Are you sure you want to deactivate this share link? All active connections will be terminated.')) {
      return;
    }

    socket.emit('share:deactivate', { shareCode }, (response: any) => {
      if (response.success) {
        onClose();
      }
    });
  };

  const pendingCount = shareLink?.pendingConnections?.length || 0;
  const activeCount = shareLink?.activeConnections?.length || 0;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            <span>Share Management</span>
            {shareLink && (
              <Badge variant={shareLink.active ? 'default' : 'secondary'}>
                {shareLink.active ? 'Active' : 'Inactive'}
              </Badge>
            )}
          </DialogTitle>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : shareLink ? (
          <div className="space-y-6">
            {/* Share Link Info */}
            <div className="bg-muted rounded-lg p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Share Code:</span>
                <code className="bg-background px-2 py-1 rounded text-sm">{shareLink.shareCode}</code>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Permission:</span>
                <div className="flex items-center gap-1">
                  {shareLink.permission === 'VIEW' ? (
                    <>
                      <Eye className="h-4 w-4" />
                      <span className="text-sm">View Only</span>
                    </>
                  ) : (
                    <>
                      <Edit3 className="h-4 w-4" />
                      <span className="text-sm">View & Control</span>
                    </>
                  )}
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Approval Mode:</span>
                <span className="text-sm">{shareLink.approvalMode.replace('_', ' ')}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Expires:</span>
                <span className="text-sm">{new Date(shareLink.expiresAt).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Usage:</span>
                <span className="text-sm">
                  {shareLink.currentUses} / {shareLink.maxUses || '∞'} connections
                </span>
              </div>
            </div>

            {/* Tabs for Pending and Active */}
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="pending" className="flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Pending ({pendingCount})
                </TabsTrigger>
                <TabsTrigger value="active" className="flex items-center gap-2">
                  <Users className="h-4 w-4" />
                  Active ({activeCount})
                </TabsTrigger>
              </TabsList>

              {/* Pending Requests */}
              <TabsContent value="pending" className="space-y-3">
                {pendingCount === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    No pending access requests
                  </div>
                ) : (
                  shareLink.pendingConnections?.map((conn) => (
                    <div key={conn.id} className="border rounded-lg p-4 space-y-3">
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="font-medium">{conn.name}</h4>
                          {conn.email && (
                            <p className="text-sm text-muted-foreground">{conn.email}</p>
                          )}
                          {conn.organization && (
                            <p className="text-sm text-muted-foreground">
                              {conn.organization}
                            </p>
                          )}
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {new Date(conn.requestedAt).toLocaleString()}
                        </span>
                      </div>

                      {conn.reason && (
                        <div className="bg-muted rounded p-2">
                          <p className="text-sm italic">"{conn.reason}"</p>
                        </div>
                      )}

                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          variant="default"
                          onClick={() => handleApprove(conn.id)}
                          className="flex-1"
                        >
                          <CheckCircle className="h-4 w-4 mr-1" />
                          Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleReject(conn.id)}
                          className="flex-1"
                        >
                          <XCircle className="h-4 w-4 mr-1" />
                          Reject
                        </Button>
                      </div>
                    </div>
                  ))
                )}
              </TabsContent>

              {/* Active Connections */}
              <TabsContent value="active" className="space-y-3">
                {activeCount === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    No active connections
                  </div>
                ) : (
                  shareLink.activeConnections?.map((conn) => (
                    <div key={conn.id} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <h4 className="font-medium">{conn.name}</h4>
                          {conn.email && (
                            <p className="text-sm text-muted-foreground">{conn.email}</p>
                          )}
                          {conn.organization && (
                            <p className="text-sm text-muted-foreground">
                              {conn.organization}
                            </p>
                          )}
                          <p className="text-xs text-muted-foreground mt-1">
                            Connected: {new Date(conn.connectedAt).toLocaleString()}
                          </p>
                        </div>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleKick(conn.id)}
                        >
                          <UserX className="h-4 w-4 mr-1" />
                          Kick
                        </Button>
                      </div>
                    </div>
                  ))
                )}
              </TabsContent>
            </Tabs>

            {/* Actions */}
            <div className="flex gap-2 pt-4 border-t">
              <Button
                variant="destructive"
                onClick={handleDeactivate}
                disabled={!shareLink.active}
                className="flex-1"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Deactivate Share Link
              </Button>
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
            </div>
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            No share link found
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
