import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from './ui/dialog';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from './ui/select';
import { Badge } from './ui/badge';
import { Share2, X, UserPlus, Shield, Eye } from 'lucide-react';
import {
  shareTerminal,
  getTerminalCollaborators,
  revokeTerminalAccess,
  updateTerminalPermission,
  unshareTerminal,
} from '../lib/terminalSharingApi';
import { useAuth } from '../contexts/AuthContext';

interface Collaborator {
  userId: string;
  username: string;
  email: string;
  permission: 'VIEW' | 'CONTROL';
  grantedAt: string;
}

interface TerminalSharingDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  terminalId: string;
  terminalTitle?: string;
}

export function TerminalSharingDialog({
  open,
  onOpenChange,
  terminalId,
  terminalTitle = 'Terminal',
}: TerminalSharingDialogProps) {
  const { user } = useAuth();
  const [collaborators, setCollaborators] = useState<Collaborator[]>([]);
  const [owner, setOwner] = useState<{ id: string; username: string; email: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Add user form
  const [userEmail, setUserEmail] = useState('');
  const [permission, setPermission] = useState<'VIEW' | 'CONTROL'>('VIEW');
  const [expiresIn, setExpiresIn] = useState<string>('never');

  useEffect(() => {
    if (open) {
      loadCollaborators();
    }
  }, [open, terminalId]);

  const loadCollaborators = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getTerminalCollaborators(terminalId);
      setOwner(data.owner);
      setCollaborators(data.collaborators);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load collaborators');
    } finally {
      setLoading(false);
    }
  };

  const handleShare = async () => {
    if (!userEmail.trim()) {
      setError('Please enter a user email');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Calculate expiration if needed
      let expiresAt: string | undefined;
      if (expiresIn !== 'never') {
        const hours = parseInt(expiresIn);
        const expDate = new Date(Date.now() + hours * 60 * 60 * 1000);
        expiresAt = expDate.toISOString();
      }

      // For demo, we'll need to get user ID from email
      // In real implementation, you'd have a user search endpoint
      await shareTerminal(terminalId, {
        userIds: [userEmail], // This should be user IDs from a search
        permission,
        expiresAt,
      });

      setUserEmail('');
      setPermission('VIEW');
      setExpiresIn('never');
      await loadCollaborators();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to share terminal');
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeAccess = async (userId: string) => {
    try {
      setLoading(true);
      setError(null);
      await revokeTerminalAccess(terminalId, userId);
      await loadCollaborators();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke access');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePermission = async (userId: string, newPermission: 'VIEW' | 'CONTROL') => {
    try {
      setLoading(true);
      setError(null);
      await updateTerminalPermission(terminalId, userId, newPermission);
      await loadCollaborators();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update permission');
    } finally {
      setLoading(false);
    }
  };

  const handleUnshareAll = async () => {
    if (!confirm('Remove all collaborators from this terminal?')) {
      return;
    }

    try {
      setLoading(true);
      setError(null);
      await unshareTerminal(terminalId);
      await loadCollaborators();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unshare terminal');
    } finally {
      setLoading(false);
    }
  };

  const isOwner = owner && user && owner.id === user.id;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="h-5 w-5" />
            Share {terminalTitle}
          </DialogTitle>
          <DialogDescription>
            Invite users to view or control this terminal session.
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg bg-destructive/10 p-3 text-sm text-destructive">
            {error}
          </div>
        )}

        {/* Owner Info */}
        {owner && (
          <div className="rounded-lg border p-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium">Owner</div>
                <div className="text-sm text-muted-foreground">{owner.username}</div>
              </div>
              <Badge variant="secondary">
                <Shield className="mr-1 h-3 w-3" />
                Owner
              </Badge>
            </div>
          </div>
        )}

        {/* Add User Form */}
        {isOwner && (
          <div className="space-y-4 rounded-lg border p-4">
            <div className="flex items-center gap-2">
              <UserPlus className="h-4 w-4" />
              <span className="text-sm font-medium">Add Collaborator</span>
            </div>

            <div className="grid gap-3">
              <div className="grid gap-2">
                <Label htmlFor="userEmail">User Email or ID</Label>
                <Input
                  id="userEmail"
                  placeholder="user@example.com"
                  value={userEmail}
                  onChange={(e) => setUserEmail(e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-2">
                  <Label htmlFor="permission">Permission Level</Label>
                  <Select
                    value={permission}
                    onValueChange={(value: 'VIEW' | 'CONTROL') => setPermission(value)}
                    disabled={loading}
                  >
                    <SelectTrigger id="permission">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="VIEW">
                        <div className="flex items-center gap-2">
                          <Eye className="h-4 w-4" />
                          <span>View Only</span>
                        </div>
                      </SelectItem>
                      <SelectItem value="CONTROL">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4" />
                          <span>Full Control</span>
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="expiresIn">Expires In</Label>
                  <Select value={expiresIn} onValueChange={setExpiresIn} disabled={loading}>
                    <SelectTrigger id="expiresIn">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="never">Never</SelectItem>
                      <SelectItem value="1">1 Hour</SelectItem>
                      <SelectItem value="24">24 Hours</SelectItem>
                      <SelectItem value="168">1 Week</SelectItem>
                      <SelectItem value="720">1 Month</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Button onClick={handleShare} disabled={loading || !userEmail.trim()}>
                Share Terminal
              </Button>
            </div>
          </div>
        )}

        {/* Collaborators List */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">
              Collaborators ({collaborators.length})
            </span>
            {isOwner && collaborators.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleUnshareAll}
                disabled={loading}
                className="text-destructive hover:text-destructive"
              >
                Remove All
              </Button>
            )}
          </div>

          {collaborators.length === 0 ? (
            <div className="rounded-lg border border-dashed p-8 text-center">
              <p className="text-sm text-muted-foreground">
                No collaborators yet. Share this terminal to get started.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {collaborators.map((collab) => (
                <div
                  key={collab.userId}
                  className="flex items-center justify-between rounded-lg border p-3"
                >
                  <div className="flex-1">
                    <div className="font-medium">{collab.username}</div>
                    <div className="text-sm text-muted-foreground">{collab.email}</div>
                  </div>

                  <div className="flex items-center gap-2">
                    {isOwner ? (
                      <Select
                        value={collab.permission}
                        onValueChange={(value: 'VIEW' | 'CONTROL') =>
                          handleUpdatePermission(collab.userId, value)
                        }
                        disabled={loading}
                      >
                        <SelectTrigger className="w-[140px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="VIEW">View Only</SelectItem>
                          <SelectItem value="CONTROL">Full Control</SelectItem>
                        </SelectContent>
                      </Select>
                    ) : (
                      <Badge variant={collab.permission === 'CONTROL' ? 'default' : 'secondary'}>
                        {collab.permission === 'CONTROL' ? 'Full Control' : 'View Only'}
                      </Badge>
                    )}

                    {isOwner && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleRevokeAccess(collab.userId)}
                        disabled={loading}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
