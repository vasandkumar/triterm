import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../../components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../../components/ui/alert-dialog';
import { Badge } from '../../components/ui/badge';
import { Users, Shield, UserX, AlertCircle, RefreshCw, CheckCircle, XCircle } from 'lucide-react';
import { getAllUsers, updateUserRole, deleteUser, activateUser, deactivateUser } from '../../lib/adminApi';
import type { User } from '../../lib/adminApi';
import { useAuth } from '../../contexts/AuthContext';

export function UserManagement() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  const [updatingRole, setUpdatingRole] = useState<string | null>(null);
  const [togglingStatus, setTogglingStatus] = useState<string | null>(null);

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      setError(null);
      setLoading(true);
      const data = await getAllUsers();
      setUsers(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: 'USER' | 'ADMIN') => {
    try {
      setUpdatingRole(userId);
      await updateUserRole(userId, newRole);
      setUsers(users.map(u => u.id === userId ? { ...u, role: newRole } : u));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to update role');
    } finally {
      setUpdatingRole(null);
    }
  };

  const confirmDelete = (user: User) => {
    setUserToDelete(user);
    setDeleteDialogOpen(true);
  };

  const handleDelete = async () => {
    if (!userToDelete) return;

    try {
      await deleteUser(userToDelete.id);
      setUsers(users.filter(u => u.id !== userToDelete.id));
      setDeleteDialogOpen(false);
      setUserToDelete(null);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete user');
    }
  };

  const handleActivate = async (userId: string) => {
    if (!confirm('Are you sure you want to activate this user? They will be able to login and create terminals.')) {
      return;
    }

    try {
      setTogglingStatus(userId);
      const updatedUser = await activateUser(userId);
      setUsers(users.map(u => u.id === userId ? updatedUser : u));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to activate user');
    } finally {
      setTogglingStatus(null);
    }
  };

  const handleDeactivate = async (userId: string) => {
    if (!confirm('Are you sure you want to deactivate this user? They will not be able to login or create terminals.')) {
      return;
    }

    try {
      setTogglingStatus(userId);
      const updatedUser = await deactivateUser(userId);
      setUsers(users.map(u => u.id === userId ? updatedUser : u));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to deactivate user');
    } finally {
      setTogglingStatus(null);
    }
  };

  const formatDate = (date: string | Date) => {
    return new Date(date).toLocaleString();
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            User Management
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
            Error Loading Users
          </CardTitle>
          <CardDescription>{error}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={loadUsers}>Retry</Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                User Management
              </CardTitle>
              <CardDescription>
                Manage user accounts and permissions ({users.length} total)
              </CardDescription>
            </div>
            <Button onClick={loadUsers} variant="outline" size="sm">
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Username</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      No users found
                    </TableCell>
                  </TableRow>
                ) : (
                  users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell className="font-medium">
                        {user.username}
                        {user.id === currentUser?.id && (
                          <Badge variant="outline" className="ml-2">You</Badge>
                        )}
                      </TableCell>
                      <TableCell>{user.email}</TableCell>
                      <TableCell>
                        <Select
                          value={user.role}
                          onValueChange={(value) => handleRoleChange(user.id, value as 'USER' | 'ADMIN')}
                          disabled={user.id === currentUser?.id || updatingRole === user.id}
                        >
                          <SelectTrigger className="w-32">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="USER">
                              <div className="flex items-center gap-2">
                                <Users className="h-4 w-4" />
                                User
                              </div>
                            </SelectItem>
                            <SelectItem value="ADMIN">
                              <div className="flex items-center gap-2">
                                <Shield className="h-4 w-4" />
                                Admin
                              </div>
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        <Badge variant={user.isActive ? 'default' : 'secondary'}>
                          {user.isActive ? 'Active' : 'Inactive'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(user.createdAt)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          {user.isActive ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleDeactivate(user.id)}
                              disabled={user.id === currentUser?.id || togglingStatus === user.id}
                              className="text-orange-500 hover:text-orange-600"
                              title="Deactivate user"
                            >
                              <XCircle className="h-4 w-4" />
                            </Button>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleActivate(user.id)}
                              disabled={togglingStatus === user.id}
                              className="text-green-500 hover:text-green-600"
                              title="Activate user"
                            >
                              <CheckCircle className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => confirmDelete(user)}
                            disabled={user.id === currentUser?.id}
                            className="text-destructive hover:text-destructive"
                            title="Delete user"
                          >
                            <UserX className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete user <strong>{userToDelete?.username}</strong>?
              This action cannot be undone and will delete all associated data including terminal sessions and recordings.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setUserToDelete(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className="bg-destructive hover:bg-destructive/90">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
