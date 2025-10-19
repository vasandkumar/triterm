import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import {
  Server,
  Database,
  AlertCircle,
  RefreshCw,
  Clock,
  Settings2,
} from 'lucide-react';
import { getSystemStats } from '../../lib/adminApi';
import type { SystemStats } from '../../lib/adminApi';

export function SystemSettings() {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadStats();
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
