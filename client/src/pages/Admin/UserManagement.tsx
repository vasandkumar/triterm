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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../../components/ui/dialog';
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
import { Input } from '../../components/ui/input';
import { Label } from '../../components/ui/label';
import { Users, Shield, UserX, AlertCircle, RefreshCw, CheckCircle, XCircle, UserPlus } from 'lucide-react';
import { getAllUsers, updateUserRole, deleteUser, activateUser, deactivateUser, createUser } from '../../lib/adminApi';
import type { User, CreateUserInput } from '../../lib/adminApi';
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
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createFormData, setCreateFormData] = useState<CreateUserInput>({
    email: '',
    username: '',
    password: '',
    role: 'USER',
    isActive: true,
  });
  const [createErrors, setCreateErrors] = useState<string[]>([]);

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

  const openCreateDialog = () => {
    setCreateFormData({
      email: '',
      username: '',
      password: '',
      role: 'USER',
      isActive: true,
    });
    setCreateErrors([]);
    setCreateDialogOpen(true);
  };

  const handleCreateUser = async () => {
    try {
      setCreateErrors([]);
      setCreating(true);

      const newUser = await createUser(createFormData);
      setUsers([newUser, ...users]);
      setCreateDialogOpen(false);
      setCreateFormData({
        email: '',
        username: '',
        password: '',
        role: 'USER',
        isActive: true,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create user';

      // Parse validation errors if they exist
      if (errorMessage.includes('Validation failed')) {
        try {
          const errorData = JSON.parse(errorMessage.split('Validation failed: ')[1] || '[]');
          setCreateErrors(errorData.map((e: any) => e.message || e));
        } catch {
          setCreateErrors([errorMessage]);
        }
      } else {
        setCreateErrors([errorMessage]);
      }
    } finally {
      setCreating(false);
    }
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
            <div className="flex items-center gap-2">
              <Button onClick={openCreateDialog} variant="default" size="sm">
                <UserPlus className="h-4 w-4 mr-2" />
                Create User
              </Button>
              <Button onClick={loadUsers} variant="outline" size="sm">
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
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

      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserPlus className="h-5 w-5" />
              Create New User
            </DialogTitle>
            <DialogDescription>
              Create a new user account. The user will be able to login immediately if active.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            {createErrors.length > 0 && (
              <div className="p-3 rounded-md bg-destructive/10 border border-destructive/20">
                <div className="flex items-start gap-2">
                  <AlertCircle className="h-4 w-4 text-destructive mt-0.5" />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-destructive">Validation errors:</p>
                    <ul className="list-disc list-inside text-sm text-destructive mt-1">
                      {createErrors.map((error, index) => (
                        <li key={index}>{error}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            <div className="grid gap-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="user@example.com"
                value={createFormData.email}
                onChange={(e) => setCreateFormData({ ...createFormData, email: e.target.value })}
                disabled={creating}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                placeholder="johndoe"
                value={createFormData.username}
                onChange={(e) => setCreateFormData({ ...createFormData, username: e.target.value })}
                disabled={creating}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Min 12 chars, uppercase, lowercase, number, special"
                value={createFormData.password}
                onChange={(e) => setCreateFormData({ ...createFormData, password: e.target.value })}
                disabled={creating}
              />
              <p className="text-xs text-muted-foreground">
                Min 12 characters with uppercase, lowercase, number, and special character
              </p>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="role">Role</Label>
              <Select
                value={createFormData.role}
                onValueChange={(value: 'USER' | 'ADMIN') =>
                  setCreateFormData({ ...createFormData, role: value })
                }
                disabled={creating}
              >
                <SelectTrigger id="role">
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
            </div>

            <div className="flex items-center gap-2">
              <input
                id="isActive"
                type="checkbox"
                checked={createFormData.isActive}
                onChange={(e) => setCreateFormData({ ...createFormData, isActive: e.target.checked })}
                disabled={creating}
                className="h-4 w-4 rounded border-gray-300"
              />
              <Label htmlFor="isActive" className="cursor-pointer">
                Active (user can login immediately)
              </Label>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setCreateDialogOpen(false)}
              disabled={creating}
            >
              Cancel
            </Button>
            <Button onClick={handleCreateUser} disabled={creating}>
              {creating ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Creating...
                </>
              ) : (
                <>
                  <UserPlus className="h-4 w-4 mr-2" />
                  Create User
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
