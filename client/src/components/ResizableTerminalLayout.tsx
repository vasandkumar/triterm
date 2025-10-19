import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { Terminal } from './Terminal';
import type { Socket } from 'socket.io-client';

interface ResizableTerminalLayoutProps {
  terminalIds: string[];
  socket: Socket;
  onClose: (terminalId: string) => void;
  onRename: (terminalId: string, newName: string) => void;
  onCommand: (command: string, terminalId?: string) => void;
}

export function ResizableTerminalLayout({
  terminalIds,
  socket,
  onClose,
  onRename,
  onCommand,
}: ResizableTerminalLayoutProps) {
  // Single terminal - no need for resizing
  if (terminalIds.length === 1) {
    return (
      <div className="h-full w-full">
        <Terminal
          key={terminalIds[0]}
          terminalId={terminalIds[0]}
          socket={socket}
          onClose={() => onClose(terminalIds[0])}
          onRename={(newName) => onRename(terminalIds[0], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[0])}
        />
      </div>
    );
  }

  // Two terminals - horizontal split
  if (terminalIds.length === 2) {
    return (
      <PanelGroup direction="horizontal" className="h-full w-full">
        <Panel defaultSize={50} minSize={20}>
          <div className="h-full border rounded-md overflow-hidden">
            <Terminal
              key={terminalIds[0]}
              terminalId={terminalIds[0]}
              socket={socket}
              onClose={() => onClose(terminalIds[0])}
              onRename={(newName) => onRename(terminalIds[0], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[0])}
            />
          </div>
        </Panel>
        <PanelResizeHandle className="w-1 bg-border hover:bg-primary transition-colors" />
        <Panel defaultSize={50} minSize={20}>
          <div className="h-full border rounded-md overflow-hidden">
            <Terminal
              key={terminalIds[1]}
              terminalId={terminalIds[1]}
              socket={socket}
              onClose={() => onClose(terminalIds[1])}
              onRename={(newName) => onRename(terminalIds[1], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[1])}
            />
          </div>
        </Panel>
      </PanelGroup>
    );
  }

  // Three terminals - one on left, two stacked on right
  if (terminalIds.length === 3) {
    return (
      <PanelGroup direction="horizontal" className="h-full w-full">
        <Panel defaultSize={50} minSize={20}>
          <div className="h-full border rounded-md overflow-hidden">
            <Terminal
              key={terminalIds[0]}
              terminalId={terminalIds[0]}
              socket={socket}
              onClose={() => onClose(terminalIds[0])}
              onRename={(newName) => onRename(terminalIds[0], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[0])}
            />
          </div>
        </Panel>
        <PanelResizeHandle className="w-1 bg-border hover:bg-primary transition-colors" />
        <Panel defaultSize={50} minSize={20}>
          <PanelGroup direction="vertical">
            <Panel defaultSize={50} minSize={20}>
              <div className="h-full border rounded-md overflow-hidden">
                <Terminal
                  key={terminalIds[1]}
                  terminalId={terminalIds[1]}
                  socket={socket}
                  onClose={() => onClose(terminalIds[1])}
                  onRename={(newName) => onRename(terminalIds[1], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[1])}
                />
              </div>
            </Panel>
            <PanelResizeHandle className="h-1 bg-border hover:bg-primary transition-colors" />
            <Panel defaultSize={50} minSize={20}>
              <div className="h-full border rounded-md overflow-hidden">
                <Terminal
                  key={terminalIds[2]}
                  terminalId={terminalIds[2]}
                  socket={socket}
                  onClose={() => onClose(terminalIds[2])}
                  onRename={(newName) => onRename(terminalIds[2], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[2])}
                />
              </div>
            </Panel>
          </PanelGroup>
        </Panel>
      </PanelGroup>
    );
  }

  // Four terminals - 2x2 grid
  if (terminalIds.length === 4) {
    return (
      <PanelGroup direction="vertical" className="h-full w-full">
        <Panel defaultSize={50} minSize={20}>
          <PanelGroup direction="horizontal">
            <Panel defaultSize={50} minSize={20}>
              <div className="h-full border rounded-md overflow-hidden">
                <Terminal
                  key={terminalIds[0]}
                  terminalId={terminalIds[0]}
                  socket={socket}
                  onClose={() => onClose(terminalIds[0])}
                  onRename={(newName) => onRename(terminalIds[0], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[0])}
                />
              </div>
            </Panel>
            <PanelResizeHandle className="w-1 bg-border hover:bg-primary transition-colors" />
            <Panel defaultSize={50} minSize={20}>
              <div className="h-full border rounded-md overflow-hidden">
                <Terminal
                  key={terminalIds[1]}
                  terminalId={terminalIds[1]}
                  socket={socket}
                  onClose={() => onClose(terminalIds[1])}
                  onRename={(newName) => onRename(terminalIds[1], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[1])}
                />
              </div>
            </Panel>
          </PanelGroup>
        </Panel>
        <PanelResizeHandle className="h-1 bg-border hover:bg-primary transition-colors" />
        <Panel defaultSize={50} minSize={20}>
          <PanelGroup direction="horizontal">
            <Panel defaultSize={50} minSize={20}>
              <div className="h-full border rounded-md overflow-hidden">
                <Terminal
                  key={terminalIds[2]}
                  terminalId={terminalIds[2]}
                  socket={socket}
                  onClose={() => onClose(terminalIds[2])}
                  onRename={(newName) => onRename(terminalIds[2], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[2])}
                />
              </div>
            </Panel>
            <PanelResizeHandle className="w-1 bg-border hover:bg-primary transition-colors" />
            <Panel defaultSize={50} minSize={20}>
              <div className="h-full border rounded-md overflow-hidden">
                <Terminal
                  key={terminalIds[3]}
                  terminalId={terminalIds[3]}
                  socket={socket}
                  onClose={() => onClose(terminalIds[3])}
                  onRename={(newName) => onRename(terminalIds[3], newName)}
              onCommand={(cmd) => onCommand(cmd, terminalIds[3])}
                />
              </div>
            </Panel>
          </PanelGroup>
        </Panel>
      </PanelGroup>
    );
  }

  // 5+ terminals - use simple grid layout (no resizing for complex layouts)
  return (
    <div className="h-full w-full grid grid-cols-3 gap-1 p-1">
      {terminalIds.map((terminalId) => (
        <div key={terminalId} className="overflow-hidden border rounded-md">
          <Terminal
            terminalId={terminalId}
            socket={socket}
            onClose={() => onClose(terminalId)}
            onRename={(newName) => onRename(terminalId, newName)}
            onCommand={(cmd) => onCommand(cmd, terminalId)}
          />
        </div>
      ))}
    </div>
  );
}
