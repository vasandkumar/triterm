/**
 * Share Approval Popup Component
 *
 * Displays pending connection requests for shared terminals
 * and allows the owner to approve, reject, or block IP addresses.
 */

import { useState, useEffect } from 'react';
import { Socket } from 'socket.io-client';
import {
  User,
  Mail,
  Building2,
  FileText,
  MapPin,
  Monitor,
  Clock,
  CheckCircle,
  XCircle,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { getAccessToken } from '../lib/tokenStorage';
import { Button } from './ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from './ui/dialog';
import { Textarea } from './ui/textarea';
import { Label } from './ui/label';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';

interface PendingConnection {
  id: string;
  name: string;
  email?: string;
  organization?: string;
  reason?: string;
  ipAddress: string;
  userAgent: string;
  geoLocation?: string;
  deviceInfo?: string;
  requestedAt: string;
}

interface ShareApprovalPopupProps {
  socket: Socket | null;
  shareCode: string;
  terminalId: string;
  onClose: () => void;
}

export function ShareApprovalPopup({ socket, shareCode, onClose }: ShareApprovalPopupProps) {
  const [pendingConnections, setPendingConnections] = useState<PendingConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedConnection, setSelectedConnection] = useState<string | null>(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [showRejectDialog, setShowRejectDialog] = useState(false);
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [expandedDetails, setExpandedDetails] = useState<Set<string>>(new Set());

  // Fetch pending connections
  useEffect(() => {
    if (!socket || !shareCode) return;

    const fetchPending = () => {
      socket.emit('share:get-pending', { shareCode }, (response: any) => {
        if (response.success) {
          setPendingConnections(response.pendingConnections || []);
        }
        setLoading(false);
      });
    };

    fetchPending();

    // Listen for new join requests
    const handleNewRequest = (data: { connection: PendingConnection }) => {
      setPendingConnections((prev) => [data.connection, ...prev]);
    };

    socket.on('share:new-request', handleNewRequest);

    return () => {
      socket.off('share:new-request', handleNewRequest);
    };
  }, [socket, shareCode]);

  // Handle approve
  const handleApprove = async (connectionId: string) => {
    if (!socket) return;

    setProcessingId(connectionId);

    socket.emit('share:approve-connection', { connectionId }, (response: any) => {
      if (response.success) {
        setPendingConnections((prev) => prev.filter((c) => c.id !== connectionId));
      } else {
        alert(`Failed to approve: ${response.error}`);
      }
      setProcessingId(null);
    });
  };

  // Handle reject (show dialog first)
  const handleRejectClick = (connectionId: string) => {
    setSelectedConnection(connectionId);
    setRejectionReason('');
    setShowRejectDialog(true);
  };

  // Confirm reject
  const handleRejectConfirm = async () => {
    if (!socket || !selectedConnection) return;

    setProcessingId(selectedConnection);

    socket.emit(
      'share:reject-connection',
      {
        connectionId: selectedConnection,
        reason: rejectionReason || undefined,
      },
      (response: any) => {
        if (response.success) {
          setPendingConnections((prev) => prev.filter((c) => c.id !== selectedConnection));
          setShowRejectDialog(false);
          setSelectedConnection(null);
          setRejectionReason('');
        } else {
          alert(`Failed to reject: ${response.error}`);
        }
        setProcessingId(null);
      }
    );
  };

  // Handle block IP
  const handleBlockIP = async (connectionId: string, ipAddress: string) => {
    if (!socket) return;

    if (!confirm(`Are you sure you want to block IP address ${ipAddress}?`)) {
      return;
    }

    setProcessingId(connectionId);

    try {
      const response = await fetch(`/api/share/${shareCode}/block-ip`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${getAccessToken()}`,
        },
        body: JSON.stringify({ ipAddress }),
      });

      if (response.ok) {
        // Also reject the connection
        socket.emit(
          'share:reject-connection',
          {
            connectionId,
            reason: 'IP address blocked',
          },
          (rejectResponse: any) => {
            if (rejectResponse.success) {
              setPendingConnections((prev) => prev.filter((c) => c.id !== connectionId));
            }
            setProcessingId(null);
          }
        );
      } else {
        const data = await response.json();
        alert(`Failed to block IP: ${data.error}`);
        setProcessingId(null);
      }
    } catch (error) {
      alert('Failed to block IP address');
      setProcessingId(null);
    }
  };

  // Toggle technical details
  const toggleDetails = (connectionId: string) => {
    setExpandedDetails((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(connectionId)) {
        newSet.delete(connectionId);
      } else {
        newSet.add(connectionId);
      }
      return newSet;
    });
  };

  // Format time ago
  const formatTimeAgo = (timestamp: string): string => {
    const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000);

    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  return (
    <>
      {/* Main approval dialog */}
      <Dialog open={true} onOpenChange={onClose}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              Pending Access Requests
              {pendingConnections.length > 0 && (
                <Badge variant="secondary" className="ml-2">
                  {pendingConnections.length}
                </Badge>
              )}
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4">
            {loading ? (
              <div className="text-center py-8 text-muted-foreground">Loading...</div>
            ) : pendingConnections.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No pending requests</p>
              </div>
            ) : (
              pendingConnections.map((connection) => (
                <div key={connection.id} className="border rounded-lg p-4 space-y-3">
                  {/* User identity */}
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="rounded-full bg-primary/10 p-2">
                        <User className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-lg">{connection.name}</h3>
                        {connection.email && (
                          <div className="flex items-center gap-1 text-sm text-muted-foreground">
                            <Mail className="h-3 w-3" />
                            <span>{connection.email}</span>
                          </div>
                        )}
                        {connection.organization && (
                          <div className="flex items-center gap-1 text-sm text-muted-foreground">
                            <Building2 className="h-3 w-3" />
                            <span>{connection.organization}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span>{formatTimeAgo(connection.requestedAt)}</span>
                    </div>
                  </div>

                  {/* Reason for access */}
                  {connection.reason && (
                    <div className="space-y-1">
                      <div className="flex items-center gap-1 text-sm font-medium">
                        <FileText className="h-4 w-4" />
                        <span>Reason for Access:</span>
                      </div>
                      <div className="pl-5 text-sm text-muted-foreground bg-muted p-3 rounded-md border-l-2 border-primary">
                        "{connection.reason}"
                      </div>
                    </div>
                  )}

                  {/* Technical details (collapsible) */}
                  <div className="space-y-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs"
                      onClick={() => toggleDetails(connection.id)}
                    >
                      {expandedDetails.has(connection.id) ? (
                        <>
                          <ChevronUp className="h-3 w-3 mr-1" />
                          Hide Technical Details
                        </>
                      ) : (
                        <>
                          <ChevronDown className="h-3 w-3 mr-1" />
                          Show Technical Details
                        </>
                      )}
                    </Button>

                    {expandedDetails.has(connection.id) && (
                      <div className="pl-4 space-y-2 text-xs">
                        <div className="flex items-center gap-2 text-muted-foreground">
                          <MapPin className="h-3 w-3" />
                          <span>IP: {connection.ipAddress}</span>
                          {connection.geoLocation && <span>({connection.geoLocation})</span>}
                        </div>
                        <div className="flex items-center gap-2 text-muted-foreground">
                          <Monitor className="h-3 w-3" />
                          <span className="truncate">{connection.userAgent}</span>
                        </div>
                      </div>
                    )}
                  </div>

                  <Separator />

                  {/* Actions */}
                  <div className="flex gap-2">
                    <Button
                      onClick={() => handleApprove(connection.id)}
                      disabled={processingId === connection.id}
                      className="flex-1"
                    >
                      <CheckCircle className="h-4 w-4 mr-2" />
                      Approve
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => handleRejectClick(connection.id)}
                      disabled={processingId === connection.id}
                      className="flex-1"
                    >
                      <XCircle className="h-4 w-4 mr-2" />
                      Reject
                    </Button>
                    <Button
                      variant="destructive"
                      onClick={() => handleBlockIP(connection.id, connection.ipAddress)}
                      disabled={processingId === connection.id}
                      title="Block IP address"
                    >
                      <AlertTriangle className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reject confirmation dialog */}
      <Dialog open={showRejectDialog} onOpenChange={setShowRejectDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Access Request</DialogTitle>
          </DialogHeader>

          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Are you sure you want to reject this access request? You can optionally provide a reason.
            </p>

            <div className="space-y-2">
              <Label htmlFor="rejection-reason">Reason (Optional)</Label>
              <Textarea
                id="rejection-reason"
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                placeholder="e.g., Insufficient justification, Unknown person, etc."
                rows={3}
                maxLength={200}
              />
              <p className="text-xs text-muted-foreground">{rejectionReason.length}/200 characters</p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRejectDialog(false)} disabled={processingId !== null}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleRejectConfirm} disabled={processingId !== null}>
              <XCircle className="h-4 w-4 mr-2" />
              Reject Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
