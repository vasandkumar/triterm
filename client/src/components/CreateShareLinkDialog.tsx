/**
 * Create Share Link Dialog Component
 *
 * Allows terminal owners to create external share links with comprehensive
 * security and name collection settings.
 */

import { useState } from 'react';
import {
  Share2,
  Copy,
  Check,
  Shield,
  User,
  Lock,
  Clock,
  Users,
  Settings,
  Eye,
  Terminal as TerminalIcon,
  AlertCircle,
} from 'lucide-react';
import { getAccessToken } from '../lib/tokenStorage';
import { Button } from './ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from './ui/dialog';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Switch } from './ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Alert, AlertDescription } from './ui/alert';
import { Separator } from './ui/separator';

interface CreateShareLinkDialogProps {
  terminalId: string;
  sessionId: string;
  open: boolean;
  onClose: () => void;
  onShareCreated?: (shareCode: string, shareUrl: string) => void;
}

interface ShareLinkConfig {
  // Name collection settings
  requireName: boolean;
  requireEmail: boolean;
  requireReason: boolean;
  nameMinLength: number;
  nameMaxLength: number;

  // Security settings
  approvalMode: 'MANUAL' | 'AUTO' | 'PASSWORD_ONLY';
  maxConcurrentUsers: number;
  maxTotalUses: number | null;
  password: string;
  requirePassword: boolean;

  // Permissions
  permission: 'VIEW' | 'CONTROL';

  // Expiration
  expiresInHours: number;
}

export function CreateShareLinkDialog({
  terminalId,
  sessionId,
  open,
  onClose,
  onShareCreated,
}: CreateShareLinkDialogProps) {
  const [config, setConfig] = useState<ShareLinkConfig>({
    requireName: true,
    requireEmail: false,
    requireReason: false,
    nameMinLength: 2,
    nameMaxLength: 50,
    approvalMode: 'MANUAL',
    maxConcurrentUsers: 5,
    maxTotalUses: 50,
    password: '',
    requirePassword: false,
    permission: 'VIEW',
    expiresInHours: 24,
  });

  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState(false);
  const [shareCode, setShareCode] = useState('');
  const [shareUrl, setShareUrl] = useState('');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Handle create share link
  const handleCreate = async () => {
    setCreating(true);
    setError(null);

    try {
      const response = await fetch('/api/share/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${getAccessToken()}`,
        },
        body: JSON.stringify({
          terminalId,
          sessionId,
          ...config,
          password: config.requirePassword ? config.password : undefined,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Failed to create share link');
        setCreating(false);
        return;
      }

      setShareCode(data.shareCode);
      const fullUrl = `${window.location.origin}/share/${data.shareCode}`;
      setShareUrl(fullUrl);
      setCreated(true);
      setCreating(false);

      if (onShareCreated) {
        onShareCreated(data.shareCode, fullUrl);
      }
    } catch (err) {
      setError('Failed to connect to server');
      setCreating(false);
    }
  };

  // Handle copy to clipboard
  const handleCopy = async () => {
    try {
      // Try modern clipboard API first
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(shareUrl);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } else {
        // Fallback for older browsers or insecure contexts
        const textArea = document.createElement('textarea');
        textArea.value = shareUrl;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        textArea.style.top = '-9999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
          const successful = document.execCommand('copy');
          if (successful) {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          } else {
            throw new Error('Copy command failed');
          }
        } finally {
          document.body.removeChild(textArea);
        }
      }
    } catch (err) {
      console.error('Failed to copy:', err);
      alert('Failed to copy to clipboard. Please copy the link manually.');
    }
  };

  // Handle close
  const handleClose = () => {
    if (created) {
      // Reset state
      setCreated(false);
      setShareCode('');
      setShareUrl('');
      setConfig({
        requireName: true,
        requireEmail: false,
        requireReason: false,
        nameMinLength: 2,
        nameMaxLength: 50,
        approvalMode: 'MANUAL',
        maxConcurrentUsers: 5,
        maxTotalUses: 50,
        password: '',
        requirePassword: false,
        permission: 'VIEW',
        expiresInHours: 24,
      });
    }
    onClose();
  };

  // Success view (after creation)
  if (created) {
    return (
      <Dialog open={open} onOpenChange={handleClose}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Check className="h-5 w-5 text-green-600" />
              Share Link Created
            </DialogTitle>
            <DialogDescription>Your share link is ready to use</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Share URL */}
            <div className="space-y-2">
              <Label>Share Link</Label>
              <div className="flex gap-2">
                <Input value={shareUrl} readOnly className="font-mono text-sm" />
                <Button onClick={handleCopy} variant="outline">
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">Share this link with people who need access</p>
            </div>

            {/* Quick stats */}
            <div className="grid grid-cols-2 gap-3">
              <div className="border rounded-lg p-3">
                <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                  <Shield className="h-4 w-4" />
                  <span>Approval Mode</span>
                </div>
                <p className="font-semibold">
                  {config.approvalMode === 'MANUAL'
                    ? 'Manual Approval'
                    : config.approvalMode === 'AUTO'
                    ? 'Auto-Approve'
                    : 'Password Only'}
                </p>
              </div>

              <div className="border rounded-lg p-3">
                <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                  <TerminalIcon className="h-4 w-4" />
                  <span>Permission</span>
                </div>
                <p className="font-semibold">{config.permission === 'VIEW' ? 'View Only' : 'View & Control'}</p>
              </div>

              <div className="border rounded-lg p-3">
                <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                  <Clock className="h-4 w-4" />
                  <span>Expires In</span>
                </div>
                <p className="font-semibold">{config.expiresInHours} hours</p>
              </div>

              <div className="border rounded-lg p-3">
                <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                  <Users className="h-4 w-4" />
                  <span>Max Users</span>
                </div>
                <p className="font-semibold">{config.maxConcurrentUsers} concurrent</p>
              </div>
            </div>

            {config.requirePassword && (
              <Alert>
                <Lock className="h-4 w-4" />
                <AlertDescription>
                  <strong>Password Protected:</strong> Users will need the password you set to join.
                </AlertDescription>
              </Alert>
            )}
          </div>

          <DialogFooter>
            <Button onClick={handleClose}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  // Configuration view
  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="h-5 w-5 text-primary" />
            Create Share Link
          </DialogTitle>
          <DialogDescription>Configure external sharing settings for this terminal</DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="security" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="user-info">User Info</TabsTrigger>
            <TabsTrigger value="limits">Limits</TabsTrigger>
          </TabsList>

          {/* Security Tab */}
          <TabsContent value="security" className="space-y-4">
            {/* Approval Mode */}
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Approval Mode
              </Label>
              <Select
                value={config.approvalMode}
                onValueChange={(value: any) => setConfig({ ...config, approvalMode: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="MANUAL">Manual Approval (Recommended)</SelectItem>
                  <SelectItem value="AUTO">Auto-Approve All</SelectItem>
                  <SelectItem value="PASSWORD_ONLY">Password Only (No Approval)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {config.approvalMode === 'MANUAL' && 'You must manually approve each join request'}
                {config.approvalMode === 'AUTO' && 'Users are automatically granted access'}
                {config.approvalMode === 'PASSWORD_ONLY' && 'Only password is required, no approval needed'}
              </p>
            </div>

            <Separator />

            {/* Permission Level */}
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <TerminalIcon className="h-4 w-4" />
                Permission Level
              </Label>
              <Select
                value={config.permission}
                onValueChange={(value: any) => setConfig({ ...config, permission: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="VIEW">
                    <div className="flex items-center gap-2">
                      <Eye className="h-4 w-4" />
                      <span>View Only (Read-only)</span>
                    </div>
                  </SelectItem>
                  <SelectItem value="CONTROL">
                    <div className="flex items-center gap-2">
                      <TerminalIcon className="h-4 w-4" />
                      <span>View & Control (Can type)</span>
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {config.permission === 'VIEW'
                  ? 'Users can only watch terminal output'
                  : 'Users can type commands and interact with the terminal'}
              </p>
            </div>

            <Separator />

            {/* Password Protection */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label htmlFor="require-password" className="flex items-center gap-2">
                  <Lock className="h-4 w-4" />
                  Require Password
                </Label>
                <Switch
                  id="require-password"
                  checked={config.requirePassword}
                  onCheckedChange={(checked) => setConfig({ ...config, requirePassword: checked })}
                />
              </div>

              {config.requirePassword && (
                <div className="pl-6">
                  <Input
                    type="password"
                    placeholder="Enter password"
                    value={config.password}
                    onChange={(e) => setConfig({ ...config, password: e.target.value })}
                    minLength={4}
                  />
                  <p className="text-xs text-muted-foreground mt-1">Minimum 4 characters</p>
                </div>
              )}
            </div>
          </TabsContent>

          {/* User Info Tab */}
          <TabsContent value="user-info" className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Choose what information external users must provide when requesting access
            </p>

            <div className="space-y-3">
              {/* Require Name */}
              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div>
                  <Label htmlFor="require-name" className="flex items-center gap-2">
                    <User className="h-4 w-4" />
                    Require Name
                  </Label>
                  <p className="text-xs text-muted-foreground mt-1">Users must provide their full name</p>
                </div>
                <Switch
                  id="require-name"
                  checked={config.requireName}
                  onCheckedChange={(checked) => setConfig({ ...config, requireName: checked })}
                />
              </div>

              {/* Name length limits */}
              {config.requireName && (
                <div className="pl-6 grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs">Min Length</Label>
                    <Input
                      type="number"
                      min={1}
                      max={config.nameMaxLength}
                      value={config.nameMinLength}
                      onChange={(e) => setConfig({ ...config, nameMinLength: parseInt(e.target.value) })}
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Max Length</Label>
                    <Input
                      type="number"
                      min={config.nameMinLength}
                      max={200}
                      value={config.nameMaxLength}
                      onChange={(e) => setConfig({ ...config, nameMaxLength: parseInt(e.target.value) })}
                    />
                  </div>
                </div>
              )}

              {/* Require Email */}
              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div>
                  <Label htmlFor="require-email" className="flex items-center gap-2">
                    Require Email
                  </Label>
                  <p className="text-xs text-muted-foreground mt-1">Users must provide their email address</p>
                </div>
                <Switch
                  id="require-email"
                  checked={config.requireEmail}
                  onCheckedChange={(checked) => setConfig({ ...config, requireEmail: checked })}
                />
              </div>

              {/* Require Reason */}
              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div>
                  <Label htmlFor="require-reason" className="flex items-center gap-2">
                    Require Reason
                  </Label>
                  <p className="text-xs text-muted-foreground mt-1">Users must explain why they need access</p>
                </div>
                <Switch
                  id="require-reason"
                  checked={config.requireReason}
                  onCheckedChange={(checked) => setConfig({ ...config, requireReason: checked })}
                />
              </div>
            </div>
          </TabsContent>

          {/* Limits Tab */}
          <TabsContent value="limits" className="space-y-4">
            {/* Expiration */}
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Expires In (Hours)
              </Label>
              <Select
                value={config.expiresInHours.toString()}
                onValueChange={(value) => setConfig({ ...config, expiresInHours: parseInt(value) })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 hour</SelectItem>
                  <SelectItem value="6">6 hours</SelectItem>
                  <SelectItem value="12">12 hours</SelectItem>
                  <SelectItem value="24">24 hours (1 day)</SelectItem>
                  <SelectItem value="48">48 hours (2 days)</SelectItem>
                  <SelectItem value="72">72 hours (3 days)</SelectItem>
                  <SelectItem value="168">168 hours (1 week)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Separator />

            {/* Max Concurrent Users */}
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Users className="h-4 w-4" />
                Max Concurrent Users
              </Label>
              <Input
                type="number"
                min={1}
                max={100}
                value={config.maxConcurrentUsers}
                onChange={(e) => setConfig({ ...config, maxConcurrentUsers: parseInt(e.target.value) || 1 })}
              />
              <p className="text-xs text-muted-foreground">Maximum number of users connected at the same time</p>
            </div>

            <Separator />

            {/* Max Total Uses */}
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Settings className="h-4 w-4" />
                Max Total Uses
              </Label>
              <Input
                type="number"
                min={1}
                max={1000}
                value={config.maxTotalUses || ''}
                onChange={(e) => setConfig({ ...config, maxTotalUses: parseInt(e.target.value) || null })}
                placeholder="Unlimited"
              />
              <p className="text-xs text-muted-foreground">
                Total number of times this link can be used (leave empty for unlimited)
              </p>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={creating}>
            Cancel
          </Button>
          <Button
            onClick={handleCreate}
            disabled={creating || (config.requirePassword && config.password.length < 4)}
          >
            {creating ? (
              <>
                <Settings className="mr-2 h-4 w-4 animate-spin" />
                Creating...
              </>
            ) : (
              <>
                <Share2 className="mr-2 h-4 w-4" />
                Create Share Link
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
