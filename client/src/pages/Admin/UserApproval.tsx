import { useEffect, useState } from 'react';
import { getPendingUsers, activateUser, User } from '../../lib/adminApi';
import { Button } from '../../components/ui/button';
import { Check, Clock, Mail, User as UserIcon } from 'lucide-react';

export function UserApproval() {
  const [pendingUsers, setPendingUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [processingId, setProcessingId] = useState<string | null>(null);

  const loadPendingUsers = async () => {
    try {
      setLoading(true);
      setError(null);
      const users = await getPendingUsers();
      setPendingUsers(users);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load pending users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPendingUsers();
  }, []);

  const handleApprove = async (userId: string) => {
    if (!confirm('Are you sure you want to approve this user?')) {
      return;
    }

    try {
      setProcessingId(userId);
      await activateUser(userId);
      // Remove from pending list
      setPendingUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to approve user');
    } finally {
      setProcessingId(null);
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="text-center text-gray-400">Loading pending users...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="p-4 bg-red-900/20 border border-red-800 rounded-lg text-red-400">
          Error: {error}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">User Approval</h2>
          <p className="text-sm text-gray-400 mt-1">
            Review and approve pending user registrations
          </p>
        </div>
        <Button onClick={loadPendingUsers} variant="outline" size="sm">
          Refresh
        </Button>
      </div>

      {pendingUsers.length === 0 ? (
        <div className="text-center py-12 bg-gray-900 border border-gray-800 rounded-lg">
          <Clock className="h-12 w-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400 mb-2">No Pending Users</h3>
          <p className="text-sm text-gray-500">
            All user registrations have been reviewed
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {pendingUsers.map((user) => (
            <div
              key={user.id}
              className="bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-gray-700 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="h-10 w-10 rounded-full bg-gray-800 flex items-center justify-center">
                      <UserIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <div>
                      <h3 className="text-white font-medium">{user.username}</h3>
                      <div className="flex items-center gap-2 text-sm text-gray-400">
                        <Mail className="h-3 w-3" />
                        {user.email}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-gray-500 ml-13">
                    <span>Role: {user.role}</span>
                    <span>•</span>
                    <span>
                      Registered: {new Date(user.createdAt).toLocaleDateString()}
                    </span>
                    {user.createdAt !== user.updatedAt && (
                      <>
                        <span>•</span>
                        <span>
                          Updated: {new Date(user.updatedAt).toLocaleDateString()}
                        </span>
                      </>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    onClick={() => handleApprove(user.id)}
                    disabled={processingId === user.id}
                    size="sm"
                    className="bg-green-600 hover:bg-green-700 text-white"
                  >
                    <Check className="h-4 w-4 mr-1" />
                    Approve
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {pendingUsers.length > 0 && (
        <div className="flex items-center justify-between p-4 bg-blue-900/20 border border-blue-800 rounded-lg">
          <div className="flex items-center gap-2 text-blue-400">
            <Clock className="h-5 w-5" />
            <span className="text-sm font-medium">
              {pendingUsers.length} user{pendingUsers.length !== 1 ? 's' : ''} waiting for approval
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
