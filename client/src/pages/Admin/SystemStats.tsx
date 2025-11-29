import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import {
  Users,
  Terminal,
  Clock,
  TrendingUp,
  Database,
  Server,
  AlertCircle
} from 'lucide-react';
import { getSystemStats } from '../../lib/adminApi';
import type { SystemStats as SystemStatsType } from '../../lib/adminApi';

export function SystemStats() {
  const [stats, setStats] = useState<SystemStatsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadStats();
    // Refresh stats every 30 seconds
    const interval = setInterval(loadStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadStats = async () => {
    try {
      setError(null);
      const data = await getSystemStats();
      setStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load stats');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        {[...Array(8)].map((_, i) => (
          <Card key={i}>
            <CardHeader className="animate-pulse">
              <div className="h-4 bg-muted rounded w-24"></div>
            </CardHeader>
            <CardContent className="animate-pulse">
              <div className="h-8 bg-muted rounded w-16"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (error || !stats) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <AlertCircle className="h-5 w-5" />
            Error Loading Stats
          </CardTitle>
          <CardDescription>{error || 'Unknown error occurred'}</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const statCards = [
    {
      title: 'Total Users',
      value: stats.totalUsers,
      icon: Users,
      description: `${stats.activeUsers} active`,
      color: 'text-blue-500'
    },
    {
      title: 'Active Sessions',
      value: stats.activeSessions,
      icon: Terminal,
      description: `${stats.totalSessions} total`,
      color: 'text-green-500'
    },
    {
      title: 'Uptime',
      value: formatUptime(stats.uptime),
      icon: Clock,
      description: 'System uptime',
      color: 'text-orange-500'
    },
    {
      title: 'CPU Usage',
      value: `${Math.round((stats.system?.cpuUsage || 0) * 100)}%`,
      icon: TrendingUp,
      description: 'Current load',
      color: 'text-red-500'
    },
    {
      title: 'Memory Usage',
      value: `${Math.round((stats.system?.memoryUsage || 0) * 100)}%`,
      icon: Server,
      description: formatBytes(stats.system?.totalMemory || 0),
      color: 'text-yellow-500'
    },
    {
      title: 'Database',
      value: stats.database?.size ? formatBytes(stats.database.size) : 'N/A',
      icon: Database,
      description: `${stats.database?.connections || 0} connections`,
      color: 'text-cyan-500'
    },
    {
      title: 'Audit Events',
      value: stats.recentAuditEvents || 0,
      icon: AlertCircle,
      description: 'Last 24 hours',
      color: 'text-pink-500'
    }
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat, index) => (
          <Card key={index}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <stat.icon className={`h-4 w-4 ${stat.color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stat.value}</div>
              <p className="text-xs text-muted-foreground mt-1">{stat.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Additional System Info */}
      <Card>
        <CardHeader>
          <CardTitle>System Information</CardTitle>
          <CardDescription>Detailed system and runtime information</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h4 className="text-sm font-medium mb-2">Runtime</h4>
              <dl className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Node Version:</dt>
                  <dd className="font-mono">{stats.system?.nodeVersion || 'N/A'}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Platform:</dt>
                  <dd className="font-mono">{stats.system?.platform || 'N/A'}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Architecture:</dt>
                  <dd className="font-mono">{stats.system?.arch || 'N/A'}</dd>
                </div>
              </dl>
            </div>
            <div>
              <h4 className="text-sm font-medium mb-2">Resources</h4>
              <dl className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Free Memory:</dt>
                  <dd className="font-mono">{formatBytes(stats.system?.freeMemory || 0)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Load Average:</dt>
                  <dd className="font-mono">{stats.system?.loadAverage?.join(', ') || 'N/A'}</dd>
                </div>
              </dl>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}
