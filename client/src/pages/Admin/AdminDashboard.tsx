import { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { Button } from '../../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/tabs';
import {
  Users,
  Activity,
  Shield,
  FileText,
  ArrowLeft,
  BarChart3,
  Settings,
  UserCheck
} from 'lucide-react';
import { UserManagement } from './UserManagement';
import { SystemStats } from './SystemStats';
import { AuditLogs } from './AuditLogs';
import { SessionMonitor } from './SessionMonitor';
import { SystemSettings } from './SystemSettings';
import { UserApproval } from './UserApproval';

export function AdminDashboard() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');

  // Redirect back to main app
  const goBack = () => {
    window.location.href = '/';
  };

  // Check if user is admin
  if (user?.role !== 'ADMIN') {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md w-full">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <Shield className="h-5 w-5" />
              Access Denied
            </CardTitle>
            <CardDescription>
              You don't have permission to access the admin panel.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={goBack} className="w-full">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Terminal
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="icon" onClick={goBack}>
                <ArrowLeft className="h-4 w-4" />
              </Button>
              <div>
                <h1 className="text-2xl font-bold flex items-center gap-2">
                  <Shield className="h-6 w-6 text-primary" />
                  Admin Dashboard
                </h1>
                <p className="text-sm text-muted-foreground">
                  System management and monitoring
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 bg-muted rounded-md">
              <span className="text-sm font-medium">{user.username}</span>
              <span className="text-xs text-muted-foreground">({user.role})</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-6 mb-8">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4" />
              <span className="hidden sm:inline">Overview</span>
            </TabsTrigger>
            <TabsTrigger value="approval" className="flex items-center gap-2">
              <UserCheck className="h-4 w-4" />
              <span className="hidden sm:inline">Approvals</span>
            </TabsTrigger>
            <TabsTrigger value="users" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              <span className="hidden sm:inline">Users</span>
            </TabsTrigger>
            <TabsTrigger value="sessions" className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              <span className="hidden sm:inline">Sessions</span>
            </TabsTrigger>
            <TabsTrigger value="audit" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              <span className="hidden sm:inline">Audit Log</span>
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span className="hidden sm:inline">Settings</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <SystemStats />
          </TabsContent>

          <TabsContent value="approval">
            <UserApproval />
          </TabsContent>

          <TabsContent value="users">
            <UserManagement />
          </TabsContent>

          <TabsContent value="sessions">
            <SessionMonitor />
          </TabsContent>

          <TabsContent value="audit">
            <AuditLogs />
          </TabsContent>

          <TabsContent value="settings">
            <SystemSettings />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
