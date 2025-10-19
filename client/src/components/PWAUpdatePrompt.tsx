import { useEffect, useState } from 'react';
import { useRegisterSW } from 'virtual:pwa-register/react';
import { Button } from './ui/button';
import { RefreshCw, X } from 'lucide-react';

export function PWAUpdatePrompt() {
  const [showPrompt, setShowPrompt] = useState(false);

  const {
    offlineReady: [offlineReady, setOfflineReady],
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({
    onRegistered(r) {
      console.log('SW Registered:', r);
    },
    onRegisterError(error) {
      console.error('SW registration error', error);
    },
  });

  useEffect(() => {
    if (offlineReady || needRefresh) {
      setShowPrompt(true);
    }
  }, [offlineReady, needRefresh]);

  const handleClose = () => {
    setOfflineReady(false);
    setNeedRefresh(false);
    setShowPrompt(false);
  };

  const handleUpdate = () => {
    updateServiceWorker(true);
  };

  if (!showPrompt) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-md">
      <div className="bg-card border rounded-lg shadow-lg p-4">
        <div className="flex items-start gap-3">
          <div className="flex-1">
            {needRefresh && (
              <>
                <h3 className="font-semibold text-sm mb-1">Update Available</h3>
                <p className="text-xs text-muted-foreground mb-3">
                  A new version of TriTerm is available. Reload to update.
                </p>
                <div className="flex gap-2">
                  <Button size="sm" onClick={handleUpdate} className="gap-2">
                    <RefreshCw className="h-3 w-3" />
                    Reload
                  </Button>
                  <Button size="sm" variant="ghost" onClick={handleClose}>
                    Later
                  </Button>
                </div>
              </>
            )}
            {offlineReady && !needRefresh && (
              <>
                <h3 className="font-semibold text-sm mb-1">Ready for Offline Use</h3>
                <p className="text-xs text-muted-foreground mb-3">
                  TriTerm is now available offline!
                </p>
                <Button size="sm" onClick={handleClose}>
                  Got it
                </Button>
              </>
            )}
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={handleClose}
            aria-label="Close notification"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
