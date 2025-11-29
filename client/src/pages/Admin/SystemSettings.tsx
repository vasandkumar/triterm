import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Switch } from '../../components/ui/switch';
import {
  Server,
  Database,
  AlertCircle,
  RefreshCw,
  Clock,
  Settings2,
  UserPlus,
  ShieldCheck,
} from 'lucide-react';
import { getSystemStats, getSystemSettings, toggleSignup } from '../../lib/adminApi';
import type { SystemStats, SystemSettings as SystemSettingsType } from '../../lib/adminApi';

export function SystemSettings() {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [settings, setSettings] = useState<SystemSettingsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [settingsLoading, setSettingsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState(false);

  useEffect(() => {
    loadStats();
    loadSettings();
  }, []);

  const loadStats = async () => {
    try {
      setError(null);
      const data = await getSystemStats();
      setStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load system stats');
    } finally {
      setLoading(false);
    }
  };

  const loadSettings = async () => {
    try {
      const data = await getSystemSettings();
      setSettings(data);
    } catch (err) {
      console.error('Failed to load system settings:', err);
    } finally {
      setSettingsLoading(false);
    }
  };

  const handleToggleSignup = async () => {
    if (!settings) return;

    const newValue = !settings.signupEnabled;
    const confirmMessage = newValue
      ? 'Enable user signup? New users will be able to register (pending admin approval).'
      : 'Disable user signup? New users will not be able to register.';

    if (!confirm(confirmMessage)) {
      return;
    }

    try {
      setToggling(true);
      const updated = await toggleSignup(newValue);
      setSettings(updated);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to toggle signup');
    } finally {
      setToggling(false);
    }
  };

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else {
      return `${minutes}m`;
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings2 className="h-5 w-5" />
            System Settings
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <AlertCircle className="h-5 w-5" />
            Error Loading Settings
          </CardTitle>
          <CardDescription>{error}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={loadStats}>Retry</Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* User Signup Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserPlus className="h-5 w-5" />
            User Signup
          </CardTitle>
          <CardDescription>
            Control whether new users can register accounts
          </CardDescription>
        </CardHeader>
        <CardContent>
          {settingsLoading ? (
            <div className="flex items-center justify-center py-4">
              <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 border rounded-lg bg-card">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-medium">Enable Signup</h4>
                    <Badge variant={settings?.signupEnabled ? 'default' : 'secondary'}>
                      {settings?.signupEnabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {settings?.signupEnabled
                      ? 'New users can register. Accounts require admin approval before activation.'
                      : 'New user registration is disabled. Only admins can create accounts.'}
                  </p>
                </div>
                <Switch
                  checked={settings?.signupEnabled || false}
                  onCheckedChange={handleToggleSignup}
                  disabled={toggling}
                />
              </div>

              <div className="p-4 border rounded-lg bg-blue-900/10 border-blue-800/50">
                <div className="flex items-start gap-2">
                  <ShieldCheck className="h-5 w-5 text-blue-400 mt-0.5" />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-blue-400">Security Note</p>
                    <p className="text-sm text-gray-400">
                      All new user registrations require admin approval before accounts are activated.
                      Users cannot create terminals or access the system until approved.
                    </p>
                  </div>
                </div>
              </div>

              {settings?.updatedAt && (
                <p className="text-xs text-muted-foreground">
                  Last updated: {new Date(settings.updatedAt).toLocaleString()}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Server Information */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Server Information
          </CardTitle>
          <CardDescription>
            Current server configuration and status
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground">Platform</span>
                <span className="text-sm font-medium">{stats?.system?.platform || 'Unknown'}</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground">Architecture</span>
                <span className="text-sm font-medium">{stats?.system?.arch || 'Unknown'}</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground">Node Version</span>
                <span className="text-sm font-medium">{stats?.system?.nodeVersion || 'Unknown'}</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Uptime
                </span>
                <span className="text-sm font-medium">
                  {stats?.uptime ? formatUptime(stats.uptime) : 'Unknown'}
                </span>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground">CPU Usage</span>
                <Badge variant={stats?.system?.cpuUsage && stats.system.cpuUsage > 0.8 ? 'destructive' : 'outline'}>
                  {stats?.system?.cpuUsage ? `${Math.round(stats.system.cpuUsage * 100)}%` : 'N/A'}
                </Badge>
              </div>
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground">Memory Usage</span>
                <Badge variant={stats?.system?.memoryUsage && stats.system.memoryUsage > 0.8 ? 'destructive' : 'outline'}>
                  {stats?.system?.memoryUsage ? `${Math.round(stats.system.memoryUsage * 100)}%` : 'N/A'}
                </Badge>
              </div>
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground">Total Memory</span>
                <span className="text-sm font-medium">
                  {stats?.system?.totalMemory ? formatBytes(stats.system.totalMemory) : 'Unknown'}
                </span>
              </div>
              <div className="flex items-center justify-between py-2 border-b">
                <span className="text-sm text-muted-foreground">Free Memory</span>
                <span className="text-sm font-medium">
                  {stats?.system?.freeMemory ? formatBytes(stats.system.freeMemory) : 'Unknown'}
                </span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* System Statistics */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Database & Sessions
          </CardTitle>
          <CardDescription>
            Current database and session statistics
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Total Users</span>
                <span className="text-2xl font-bold">{stats?.totalUsers || 0}</span>
              </div>
              <p className="text-xs text-muted-foreground">Registered user accounts</p>
            </div>

            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Active Users</span>
                <span className="text-2xl font-bold">{stats?.activeUsers || 0}</span>
              </div>
              <p className="text-xs text-muted-foreground">Users active in last 30 days</p>
            </div>

            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Total Sessions</span>
                <span className="text-2xl font-bold">{stats?.totalSessions || 0}</span>
              </div>
              <p className="text-xs text-muted-foreground">All terminal sessions</p>
            </div>

            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Active Sessions</span>
                <span className="text-2xl font-bold">{stats?.activeSessions || 0}</span>
              </div>
              <p className="text-xs text-muted-foreground">Currently running terminals</p>
            </div>

            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Audit Events (24h)</span>
                <span className="text-2xl font-bold">{stats?.recentAuditEvents || 0}</span>
              </div>
              <p className="text-xs text-muted-foreground">Security events logged today</p>
            </div>

            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Load Average</span>
                <span className="text-2xl font-bold">
                  {stats?.system?.loadAverage?.[0]?.toFixed(2) || 'N/A'}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">1-minute load average</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Maintenance Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings2 className="h-5 w-5" />
            Automated Maintenance
          </CardTitle>
          <CardDescription>
            Background tasks running automatically
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
              <div>
                <p className="text-sm font-medium">Session Cleanup</p>
                <p className="text-xs text-muted-foreground">
                  Automatically runs hourly to clean inactive sessions (24h+)
                </p>
              </div>
              <Badge variant="outline">Automated</Badge>
            </div>

            <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
              <div>
                <p className="text-sm font-medium">User Presence Tracking</p>
                <p className="text-xs text-muted-foreground">
                  Updates user activity status in real-time
                </p>
              </div>
              <Badge variant="outline">Active</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Refresh Button */}
      <div className="flex justify-end">
        <Button onClick={loadStats} variant="outline">
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh Statistics
        </Button>
      </div>
    </div>
  );
}
