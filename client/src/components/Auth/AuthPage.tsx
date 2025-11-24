import { useState } from 'react';
import { LoginForm } from './LoginForm';
import { RegisterForm } from './RegisterForm';

export function AuthPage() {
  const [showLogin, setShowLogin] = useState(true);

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
          {showLogin ? (
            <LoginForm onSwitchToRegister={() => setShowLogin(false)} />
          ) : (
            <RegisterForm onSwitchToLogin={() => setShowLogin(true)} />
          )}
        </div>
      </div>
    </div>
  );
}
