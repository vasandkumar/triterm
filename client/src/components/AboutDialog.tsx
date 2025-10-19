import React from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog';
import { Button } from './ui/button';
import { Separator } from './ui/separator';
import { Terminal, Github, ExternalLink, Shield, Zap, Users, Heart } from 'lucide-react';

export function AboutDialog({ open, onOpenChange }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="p-3 bg-primary/10 rounded-lg">
              <Terminal className="h-8 w-8 text-primary" />
            </div>
            <div>
              <DialogTitle className="text-2xl">TriTerm</DialogTitle>
              <p className="text-sm text-muted-foreground">Enterprise Terminal Manager v1.0.0</p>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-6 py-4">
          {/* Description */}
          <div>
            <p className="text-muted-foreground">
              TriTerm is a powerful, enterprise-level multi-terminal web application that allows you
              to run multiple terminal sessions side-by-side in your browser with real-time
              WebSocket communication.
            </p>
          </div>

          <Separator />

          {/* Features */}
          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Zap className="h-5 w-5 text-primary" />
              Key Features
            </h3>
            <ul className="grid grid-cols-2 gap-2 text-sm text-muted-foreground">
              <li className="flex items-center gap-2">
                <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                Multiple terminal sessions
              </li>
              <li className="flex items-center gap-2">
                <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                Real-time communication
              </li>
              <li className="flex items-center gap-2">
                <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                Responsive grid layout
              </li>
              <li className="flex items-center gap-2">
                <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                Terminal maximize/split
              </li>
              <li className="flex items-center gap-2">
                <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                Session management
              </li>
              <li className="flex items-center gap-2">
                <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                Secure connections
              </li>
            </ul>
          </div>

          <Separator />

          {/* Tech Stack */}
          <div>
            <h3 className="text-lg font-semibold mb-3">Technology Stack</h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 border rounded-lg">
                <div className="font-semibold text-sm mb-1">Frontend</div>
                <ul className="text-xs text-muted-foreground space-y-1">
                  <li>React 18</li>
                  <li>Vite</li>
                  <li>xterm.js</li>
                  <li>Tailwind CSS</li>
                  <li>shadcn/ui</li>
                </ul>
              </div>
              <div className="p-3 border rounded-lg">
                <div className="font-semibold text-sm mb-1">Backend</div>
                <ul className="text-xs text-muted-foreground space-y-1">
                  <li>Node.js</li>
                  <li>Express</li>
                  <li>Socket.io</li>
                  <li>node-pty</li>
                  <li>Helmet.js</li>
                </ul>
              </div>
            </div>
          </div>

          <Separator />

          {/* Security & License */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                Security
              </h3>
              <p className="text-xs text-muted-foreground">
                Enterprise-grade security with CORS protection, rate limiting, session isolation,
                and input sanitization.
              </p>
            </div>
            <div>
              <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Heart className="h-4 w-4 text-primary" />
                Open Source
              </h3>
              <p className="text-xs text-muted-foreground">
                Built with love using modern open-source technologies. View the source code on
                GitHub.
              </p>
            </div>
          </div>

          <Separator />

          {/* Links */}
          <div className="flex gap-2">
            <Button variant="outline" className="flex-1 gap-2" size="sm">
              <Github className="h-4 w-4" />
              GitHub
              <ExternalLink className="h-3 w-3 ml-auto" />
            </Button>
            <Button variant="outline" className="flex-1 gap-2" size="sm">
              <Users className="h-4 w-4" />
              Documentation
              <ExternalLink className="h-3 w-3 ml-auto" />
            </Button>
          </div>

          {/* Footer */}
          <div className="text-center text-xs text-muted-foreground pt-2">
            <p>© 2025 TriTerm. All rights reserved.</p>
            <p className="mt-1">
              Made with <Heart className="h-3 w-3 inline text-red-500" /> for developers
            </p>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
