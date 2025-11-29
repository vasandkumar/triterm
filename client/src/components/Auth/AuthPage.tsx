import { useState, useEffect } from 'react';
import { LoginForm } from './LoginForm';
import { RegisterForm } from './RegisterForm';
import { getSignupStatus } from '../../lib/authApi';

export function AuthPage() {
  const [showLogin, setShowLogin] = useState(true);
  const [signupEnabled, setSignupEnabled] = useState(false);
  const [isFirstUser, setIsFirstUser] = useState(false);
  const [signupMessage, setSignupMessage] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check signup status on mount
    async function checkSignupStatus() {
      try {
        const status = await getSignupStatus();
        setSignupEnabled(status.signupEnabled);
        setIsFirstUser(status.isFirstUser);
        setSignupMessage(status.message);
      } catch (error) {
        console.error('Failed to check signup status:', error);
        // Default to disabled if check fails
        setSignupEnabled(false);
      } finally {
        setLoading(false);
      }
    }

    checkSignupStatus();
  }, []);

  // If signup is disabled and user tries to access register, show login instead
  useEffect(() => {
    if (!loading && !showLogin && !signupEnabled) {
      setShowLogin(true);
    }
  }, [loading, showLogin, signupEnabled]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 p-4">
      <div className="w-full max-w-6xl flex items-center justify-center gap-12">
        {/* Left side - Branding */}
        <div className="hidden lg:flex flex-col space-y-6 max-w-lg">
          <div>
            <h1 className="text-5xl font-bold text-white mb-4">TriTerm</h1>
            <p className="text-xl text-gray-300">
              Web-based terminal with real-time collaboration
            </p>
          </div>

          <div className="space-y-4 text-gray-400">
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center text-white text-sm font-bold mt-1">
                ✓
              </div>
              <div>
                <h3 className="text-white font-medium">Terminal Sharing</h3>
                <p className="text-sm">Share terminals via secure links with permission controls</p>
              </div>
            </div>

            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center text-white text-sm font-bold mt-1">
                ✓
              </div>
              <div>
                <h3 className="text-white font-medium">Real-time Collaboration</h3>
                <p className="text-sm">View and interact with shared terminals in real-time</p>
              </div>
            </div>

            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center text-white text-sm font-bold mt-1">
                ✓
              </div>
              <div>
                <h3 className="text-white font-medium">Session Management</h3>
                <p className="text-sm">Multiple terminals, layouts, and persistent sessions</p>
              </div>
            </div>
          </div>
        </div>

        {/* Right side - Auth Form */}
        <div className="w-full lg:w-auto">
          {loading ? (
            <div className="w-full max-w-md p-8 space-y-6 bg-gray-900 border border-gray-800 rounded-lg">
              <div className="text-center text-gray-400">Loading...</div>
            </div>
          ) : showLogin ? (
            <LoginForm
              onSwitchToRegister={signupEnabled ? () => setShowLogin(false) : undefined}
              signupEnabled={signupEnabled}
              signupMessage={signupMessage}
            />
          ) : (
            <RegisterForm
              onSwitchToLogin={() => setShowLogin(true)}
              isFirstUser={isFirstUser}
            />
          )}
        </div>
      </div>
    </div>
  );
}
