import { useState, FormEvent } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';

interface RegisterFormProps {
  onSwitchToLogin: () => void;
  isFirstUser: boolean;
}

export function RegisterForm({ onSwitchToLogin, isFirstUser }: RegisterFormProps) {
  const { register, error, loading, clearError } = useAuth();
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [validationError, setValidationError] = useState('');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    clearError();
    setValidationError('');

    // Client-side validation
    if (password !== confirmPassword) {
      setValidationError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setValidationError('Password must be at least 8 characters');
      return;
    }

    if (!/[A-Z]/.test(password)) {
      setValidationError('Password must contain at least one uppercase letter');
      return;
    }

    if (!/[a-z]/.test(password)) {
      setValidationError('Password must contain at least one lowercase letter');
      return;
    }

    if (!/[0-9]/.test(password)) {
      setValidationError('Password must contain at least one number');
      return;
    }

    if (username.length < 3) {
      setValidationError('Username must be at least 3 characters');
      return;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      setValidationError('Username can only contain letters, numbers, underscores, and hyphens');
      return;
    }

    try {
      await register({ email, username, password });
    } catch (err) {
      // Error is handled by AuthContext
    }
  };

  const displayError = validationError || error;

  return (
    <div className="w-full max-w-md p-8 space-y-6 bg-gray-900 border border-gray-800 rounded-lg">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-white">
          {isFirstUser ? 'Create Admin Account' : 'Create TriTerm Account'}
        </h2>
        <p className="mt-2 text-sm text-gray-400">
          {isFirstUser
            ? 'Set up your administrator account to get started'
            : 'Sign up to start using web terminals'}
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {displayError && (
          <div className="p-3 text-sm text-red-400 bg-red-900/20 border border-red-800 rounded">
            {displayError}
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="email" className="text-gray-300">
            Email
          </Label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
            disabled={loading}
            className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="username" className="text-gray-300">
            Username
          </Label>
          <Input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="your_username"
            required
            disabled={loading}
            minLength={3}
            maxLength={20}
            pattern="[a-zA-Z0-9_-]+"
            className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500"
          />
          <p className="text-xs text-gray-500">3-20 characters, letters, numbers, _ and - only</p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="password" className="text-gray-300">
            Password
          </Label>
          <Input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            disabled={loading}
            minLength={8}
            className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500"
          />
          <p className="text-xs text-gray-500">
            At least 8 characters with uppercase, lowercase, and number
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="confirmPassword" className="text-gray-300">
            Confirm Password
          </Label>
          <Input
            id="confirmPassword"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="••••••••"
            required
            disabled={loading}
            className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500"
          />
        </div>

        <Button type="submit" className="w-full" disabled={loading}>
          {loading ? 'Creating Account...' : 'Create Account'}
        </Button>
      </form>

      <div className="text-center text-sm text-gray-400">
        Already have an account?{' '}
        <button
          onClick={onSwitchToLogin}
          className="text-blue-400 hover:text-blue-300 font-medium"
          disabled={loading}
        >
          Sign In
        </button>
      </div>
    </div>
  );
}
