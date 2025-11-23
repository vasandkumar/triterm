/**
 * Join Shared Terminal Component
 *
 * Allows external users to request access to a shared terminal
 * with comprehensive name collection and validation.
 */

import { useState, useEffect } from 'react';
import { io, Socket } from 'socket.io-client';
import { Loader2, Terminal, Shield, User, Mail, Building2, FileText, Lock, AlertCircle } from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Textarea } from './ui/textarea';
import { Checkbox } from './ui/checkbox';
import { Alert, AlertDescription } from './ui/alert';

interface ShareSettings {
  shareCode: string;
  requireName: boolean;
  requireEmail: boolean;
  requireReason: boolean;
  nameMinLength: number;
  nameMaxLength: number;
  allowAnonymous: boolean;
  requirePassword: boolean;
  approvalMode: 'MANUAL' | 'AUTO' | 'PASSWORD_ONLY';
  permission: 'VIEW' | 'CONTROL';
  expiresAt: string;
}

interface JoinFormData {
  name: string;
  email: string;
  organization: string;
  reason: string;
  password: string;
  acceptTerms: boolean;
}

interface ValidationErrors {
  name?: string;
  email?: string;
  reason?: string;
  password?: string;
  acceptTerms?: string;
}

interface JoinSharedTerminalProps {
  shareCode: string;
}

export function JoinSharedTerminal({ shareCode }: JoinSharedTerminalProps) {

  const [settings, setSettings] = useState<ShareSettings | null>(null);
  const [formData, setFormData] = useState<JoinFormData>({
    name: '',
    email: '',
    organization: '',
    reason: '',
    password: '',
    acceptTerms: false,
  });
  const [errors, setErrors] = useState<ValidationErrors>({});
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<'idle' | 'pending' | 'approved' | 'rejected'>('idle');
  const [connectionId, setConnectionId] = useState<string | null>(null);
  const [socket, setSocket] = useState<Socket | null>(null);

  // Fetch share link settings
  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const response = await fetch(`/api/share/${shareCode}/settings`);
        const data = await response.json();

        if (!response.ok) {
          setError(data.error || 'Failed to load share link');
          setLoading(false);
          return;
        }

        setSettings(data.settings);
        setLoading(false);
      } catch (err) {
        setError('Failed to connect to server');
        setLoading(false);
      }
    };

    if (shareCode) {
      fetchSettings();
    }
  }, [shareCode]);

  // Setup socket connection for real-time updates
  useEffect(() => {
    // Create socket connection (no auth needed for public share links)
    const newSocket = io({
      transports: ['websocket', 'polling'],
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, []);

  // Listen for approval/rejection events
  useEffect(() => {
    if (!socket || !connectionId) return;

    const handleApproved = (data: { terminalId: string }) => {
      setStatus('approved');
      // Store connectionId securely in sessionStorage instead of URL
      sessionStorage.setItem('share_connection_id', connectionId);
      sessionStorage.setItem('share_terminal_id', data.terminalId);
      // Redirect to terminal view without exposing connectionId in URL
      window.location.href = `/share/${shareCode}/terminal`;
    };

    const handleRejected = (data: { reason?: string }) => {
      setStatus('rejected');
      setError(data.reason || 'Your access request was rejected');
    };

    // Join connection-specific room
    socket.emit('share:join-connection-room', { connectionId });

    // Listen for events
    socket.on('share:connection-approved', handleApproved);
    socket.on('share:connection-rejected', handleRejected);

    return () => {
      socket.off('share:connection-approved', handleApproved);
      socket.off('share:connection-rejected', handleRejected);
    };
  }, [socket, connectionId, shareCode]);

  // Form validation
  const validateForm = (): boolean => {
    const newErrors: ValidationErrors = {};

    // Name validation
    if (settings?.requireName && !formData.name.trim()) {
      newErrors.name = 'Name is required';
    } else if (formData.name.trim()) {
      if (formData.name.length < (settings?.nameMinLength || 2)) {
        newErrors.name = `Name must be at least ${settings?.nameMinLength || 2} characters`;
      }
      if (formData.name.length > (settings?.nameMaxLength || 50)) {
        newErrors.name = `Name must not exceed ${settings?.nameMaxLength || 50} characters`;
      }
    }

    // Email validation
    if (settings?.requireEmail && !formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (formData.email.trim()) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(formData.email)) {
        newErrors.email = 'Invalid email format';
      }
    }

    // Reason validation
    if (settings?.requireReason && !formData.reason.trim()) {
      newErrors.reason = 'Reason for access is required';
    }

    // Password validation
    if (settings?.requirePassword && !formData.password) {
      newErrors.password = 'Password is required';
    }

    // Terms acceptance
    if (!formData.acceptTerms) {
      newErrors.acceptTerms = 'You must accept the terms to continue';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const response = await fetch(`/api/share/${shareCode}/join`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: formData.name,
          email: formData.email || undefined,
          organization: formData.organization || undefined,
          reason: formData.reason || undefined,
          password: formData.password || undefined,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Failed to submit join request');
        setSubmitting(false);
        return;
      }

      setConnectionId(data.connectionId);

      if (data.status === 'PENDING') {
        setStatus('pending');
      } else if (data.status === 'APPROVED') {
        setStatus('approved');
        // Redirect to terminal view
        window.location.href = `/share/${shareCode}/terminal?connectionId=${data.connectionId}`;
      }

      setSubmitting(false);
    } catch (err) {
      setError('Failed to connect to server');
      setSubmitting(false);
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading share link...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error && !settings) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background p-4">
        <div className="max-w-md w-full">
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        </div>
      </div>
    );
  }

  // Pending approval state
  if (status === 'pending') {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background p-4">
        <div className="max-w-md w-full space-y-6 text-center">
          <div className="flex justify-center">
            <div className="rounded-full bg-primary/10 p-6">
              <Shield className="h-12 w-12 text-primary" />
            </div>
          </div>

          <div className="space-y-2">
            <h2 className="text-2xl font-bold">Waiting for Approval</h2>
            <p className="text-muted-foreground">
              Your request has been submitted. The terminal owner will review your request shortly.
            </p>
          </div>

          <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>Waiting for approval...</span>
          </div>

          <div className="pt-4">
            <Button variant="outline" onClick={() => window.location.href = '/'}>
              Back to Home
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Join form
  return (
    <div className="flex items-center justify-center min-h-screen bg-background p-4">
      <div className="max-w-2xl w-full">
        <div className="bg-card border rounded-lg shadow-lg">
          {/* Header */}
          <div className="border-b p-6">
            <div className="flex items-center gap-3 mb-2">
              <div className="rounded-full bg-primary/10 p-2">
                <Terminal className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold">Join Shared Terminal</h1>
                <p className="text-sm text-muted-foreground">Code: {shareCode}</p>
              </div>
            </div>

            {/* Share info */}
            <div className="mt-4 flex flex-wrap gap-4 text-sm">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Shield className="h-4 w-4" />
                <span>
                  {settings?.approvalMode === 'MANUAL'
                    ? 'Manual Approval Required'
                    : settings?.approvalMode === 'AUTO'
                    ? 'Auto-Approved'
                    : 'Password Protected'}
                </span>
              </div>
              <div className="flex items-center gap-2 text-muted-foreground">
                <Terminal className="h-4 w-4" />
                <span>Permission: {settings?.permission === 'VIEW' ? 'View Only' : 'View & Control'}</span>
              </div>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="p-6 space-y-6">
            {/* Error alert */}
            {error && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* Name field */}
            <div className="space-y-2">
              <Label htmlFor="name" className="flex items-center gap-2">
                <User className="h-4 w-4" />
                Full Name {settings?.requireName && <span className="text-destructive">*</span>}
              </Label>
              <Input
                id="name"
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="Enter your full name"
                className={errors.name ? 'border-destructive' : ''}
                required={settings?.requireName}
              />
              {errors.name && <p className="text-sm text-destructive">{errors.name}</p>}
            </div>

            {/* Email field */}
            <div className="space-y-2">
              <Label htmlFor="email" className="flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Email {settings?.requireEmail && <span className="text-destructive">*</span>}
              </Label>
              <Input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="your.email@example.com"
                className={errors.email ? 'border-destructive' : ''}
                required={settings?.requireEmail}
              />
              {errors.email && <p className="text-sm text-destructive">{errors.email}</p>}
            </div>

            {/* Organization field */}
            <div className="space-y-2">
              <Label htmlFor="organization" className="flex items-center gap-2">
                <Building2 className="h-4 w-4" />
                Organization
                <span className="text-muted-foreground text-xs">(Optional)</span>
              </Label>
              <Input
                id="organization"
                type="text"
                value={formData.organization}
                onChange={(e) => setFormData({ ...formData, organization: e.target.value })}
                placeholder="Your company or organization"
              />
            </div>

            {/* Reason field */}
            <div className="space-y-2">
              <Label htmlFor="reason" className="flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Reason for Access {settings?.requireReason && <span className="text-destructive">*</span>}
              </Label>
              <Textarea
                id="reason"
                value={formData.reason}
                onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
                placeholder="Why do you need access to this terminal?"
                className={errors.reason ? 'border-destructive' : ''}
                rows={3}
                maxLength={500}
                required={settings?.requireReason}
              />
              {errors.reason && <p className="text-sm text-destructive">{errors.reason}</p>}
              <p className="text-xs text-muted-foreground">{formData.reason.length}/500 characters</p>
            </div>

            {/* Password field */}
            {settings?.requirePassword && (
              <div className="space-y-2">
                <Label htmlFor="password" className="flex items-center gap-2">
                  <Lock className="h-4 w-4" />
                  Password <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="password"
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  placeholder="Enter share link password"
                  className={errors.password ? 'border-destructive' : ''}
                  required
                />
                {errors.password && <p className="text-sm text-destructive">{errors.password}</p>}
              </div>
            )}

            {/* Terms checkbox */}
            <div className="space-y-2">
              <div className="flex items-start gap-2">
                <Checkbox
                  id="acceptTerms"
                  checked={formData.acceptTerms}
                  onCheckedChange={(checked) => setFormData({ ...formData, acceptTerms: checked as boolean })}
                />
                <Label htmlFor="acceptTerms" className="text-sm leading-relaxed cursor-pointer">
                  I understand that my access may be monitored and recorded. I will use this terminal responsibly
                  and only for the stated purpose.
                </Label>
              </div>
              {errors.acceptTerms && <p className="text-sm text-destructive">{errors.acceptTerms}</p>}
            </div>

            {/* Submit button */}
            <div className="flex gap-3 pt-4">
              <Button type="submit" disabled={submitting} className="flex-1">
                {submitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Submitting...
                  </>
                ) : (
                  'Request Access'
                )}
              </Button>
              <Button type="button" variant="outline" onClick={() => window.location.href = '/'}>
                Cancel
              </Button>
            </div>

            {/* Info text */}
            <p className="text-xs text-center text-muted-foreground">
              By submitting this form, you agree to comply with all applicable policies and regulations.
            </p>
          </form>
        </div>

        {/* Expiration notice */}
        {settings && (
          <div className="mt-4 text-center text-sm text-muted-foreground">
            This share link expires on {new Date(settings.expiresAt).toLocaleString()}
          </div>
        )}
      </div>
    </div>
  );
}
