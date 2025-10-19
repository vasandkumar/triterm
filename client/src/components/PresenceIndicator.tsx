import { Users, Eye, MousePointer } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import { Badge } from './ui/badge';

interface CollaboratorPresence {
  userId: string;
  username: string;
  permission: 'VIEW' | 'CONTROL';
  connectedAt: number;
  lastActivity: number;
}

interface PresenceIndicatorProps {
  collaborators: CollaboratorPresence[];
  currentUserId?: string;
}

export function PresenceIndicator({ collaborators, currentUserId }: PresenceIndicatorProps) {
  // Filter out current user from display
  const otherCollaborators = collaborators.filter((c) => c.userId !== currentUserId);

  if (otherCollaborators.length === 0) {
    return null;
  }

  const viewers = otherCollaborators.filter((c) => c.permission === 'VIEW');
  const controllers = otherCollaborators.filter((c) => c.permission === 'CONTROL');

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="flex items-center gap-1.5 px-2 py-1 bg-muted/50 rounded-md text-sm cursor-pointer hover:bg-muted transition-colors">
          <Users className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="font-medium text-foreground">{otherCollaborators.length}</span>
        </div>
      </TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-xs">
        <div className="space-y-2">
          <div className="font-semibold text-xs text-muted-foreground uppercase tracking-wide">
            Active Collaborators
          </div>

          {controllers.length > 0 && (
            <div className="space-y-1">
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <MousePointer className="h-3 w-3" />
                <span>Full Control</span>
              </div>
              {controllers.map((user) => (
                <div key={user.userId} className="flex items-center justify-between gap-2 pl-4">
                  <span className="text-sm">{user.username}</span>
                  <Badge variant="default" className="h-5 text-xs">
                    Control
                  </Badge>
                </div>
              ))}
            </div>
          )}

          {viewers.length > 0 && (
            <div className="space-y-1">
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <Eye className="h-3 w-3" />
                <span>Viewing Only</span>
              </div>
              {viewers.map((user) => (
                <div key={user.userId} className="flex items-center justify-between gap-2 pl-4">
                  <span className="text-sm">{user.username}</span>
                  <Badge variant="secondary" className="h-5 text-xs">
                    View
                  </Badge>
                </div>
              ))}
            </div>
          )}

          <div className="pt-2 border-t text-xs text-muted-foreground">
            {otherCollaborators.length === 1
              ? '1 person is collaborating'
              : `${otherCollaborators.length} people are collaborating`}
          </div>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * Minimal presence indicator for compact spaces
 */
export function PresenceIndicatorCompact({ collaborators, currentUserId }: PresenceIndicatorProps) {
  const otherCollaborators = collaborators.filter((c) => c.userId !== currentUserId);

  if (otherCollaborators.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-1">
      <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
      <span className="text-xs text-muted-foreground">
        {otherCollaborators.length} {otherCollaborators.length === 1 ? 'viewer' : 'viewers'}
      </span>
    </div>
  );
}
