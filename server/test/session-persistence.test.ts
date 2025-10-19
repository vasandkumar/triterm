import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  createTerminalSession,
  updateSessionActivity,
  updateSessionDimensions,
  deactivateSession,
  deleteSession,
  getUserActiveSessions,
  getSession,
  cleanupOldSessions,
  updateSessionSocket,
  type TerminalSessionData,
} from '../lib/terminalSession.js';
import { prisma } from '../lib/prisma.js';
import { hashPassword } from '../lib/password.js';

describe('Terminal Session Persistence', () => {
  let testUserId: string;
  let testTerminalId: string;

  // Create a test user before each test
  beforeEach(async () => {
    // Clean up existing test data
    await prisma.session.deleteMany({});
    await prisma.user.deleteMany({});

    // Create a test user
    const hashedPassword = await hashPassword('TestPass123!');
    const user = await prisma.user.create({
      data: {
        email: `test-${Date.now()}@example.com`,
        username: `testuser-${Date.now()}`,
        password: hashedPassword,
      },
    });
    testUserId = user.id;
    testTerminalId = `test-terminal-${Date.now()}`;
  });

  // Clean up after each test
  afterEach(async () => {
    await prisma.session.deleteMany({});
    await prisma.user.deleteMany({});
  });

  describe('createTerminalSession', () => {
    it('should create a new terminal session', async () => {
      const sessionData: TerminalSessionData = {
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
        socketId: 'socket-123',
      };

      const session = await createTerminalSession(sessionData);

      expect(session).toBeDefined();
      expect(session.terminalId).toBe(testTerminalId);
      expect(session.userId).toBe(testUserId);
      expect(session.shell).toBe('/bin/bash');
      expect(session.cwd).toBe('/home/user');
      expect(session.cols).toBe(80);
      expect(session.rows).toBe(24);
      expect(session.socketId).toBe('socket-123');
      expect(session.active).toBe(true);
      expect(session.lastActivityAt).toBeInstanceOf(Date);
    });

    it('should fail with duplicate terminalId', async () => {
      const sessionData: TerminalSessionData = {
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      };

      await createTerminalSession(sessionData);

      // Try to create duplicate
      await expect(createTerminalSession(sessionData)).rejects.toThrow();
    });
  });

  describe('getSession', () => {
    it('should retrieve an existing session', async () => {
      const sessionData: TerminalSessionData = {
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      };

      await createTerminalSession(sessionData);
      const session = await getSession(testTerminalId);

      expect(session).toBeDefined();
      expect(session?.terminalId).toBe(testTerminalId);
    });

    it('should return null for non-existent session', async () => {
      const session = await getSession('non-existent-id');
      expect(session).toBeNull();
    });
  });

  describe('getUserActiveSessions', () => {
    it('should return all active sessions for a user', async () => {
      // Create multiple sessions
      await createTerminalSession({
        terminalId: `${testTerminalId}-1`,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      await createTerminalSession({
        terminalId: `${testTerminalId}-2`,
        userId: testUserId,
        shell: '/bin/zsh',
        cwd: '/home/user',
        cols: 120,
        rows: 30,
      });

      const sessions = await getUserActiveSessions(testUserId);

      expect(sessions).toHaveLength(2);
      expect(sessions.every((s) => s.active)).toBe(true);
      expect(sessions.every((s) => s.userId === testUserId)).toBe(true);
    });

    it('should not return inactive sessions', async () => {
      // Create active session
      await createTerminalSession({
        terminalId: `${testTerminalId}-1`,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      // Create and deactivate another session
      await createTerminalSession({
        terminalId: `${testTerminalId}-2`,
        userId: testUserId,
        shell: '/bin/zsh',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });
      await deactivateSession(`${testTerminalId}-2`);

      const sessions = await getUserActiveSessions(testUserId);

      expect(sessions).toHaveLength(1);
      expect(sessions[0].terminalId).toBe(`${testTerminalId}-1`);
    });
  });

  describe('updateSessionActivity', () => {
    it('should update lastActivityAt timestamp', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      const sessionBefore = await getSession(testTerminalId);
      const timeBefore = sessionBefore?.lastActivityAt;

      // Wait a bit to ensure timestamp difference
      await new Promise((resolve) => setTimeout(resolve, 100));

      await updateSessionActivity(testTerminalId);

      const sessionAfter = await getSession(testTerminalId);
      const timeAfter = sessionAfter?.lastActivityAt;

      expect(timeAfter).toBeDefined();
      expect(timeBefore).toBeDefined();
      expect(timeAfter!.getTime()).toBeGreaterThan(timeBefore!.getTime());
    });

    it('should not throw for non-existent session', async () => {
      // Should silently fail
      await expect(updateSessionActivity('non-existent')).resolves.not.toThrow();
    });
  });

  describe('updateSessionDimensions', () => {
    it('should update terminal dimensions', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      await updateSessionDimensions(testTerminalId, 120, 30);

      const session = await getSession(testTerminalId);
      expect(session?.cols).toBe(120);
      expect(session?.rows).toBe(30);
    });

    it('should update lastActivityAt when updating dimensions', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      const sessionBefore = await getSession(testTerminalId);
      const timeBefore = sessionBefore?.lastActivityAt;

      await new Promise((resolve) => setTimeout(resolve, 100));
      await updateSessionDimensions(testTerminalId, 120, 30);

      const sessionAfter = await getSession(testTerminalId);
      const timeAfter = sessionAfter?.lastActivityAt;

      expect(timeAfter!.getTime()).toBeGreaterThan(timeBefore!.getTime());
    });
  });

  describe('deactivateSession', () => {
    it('should mark session as inactive and clear socketId', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
        socketId: 'socket-123',
      });

      await deactivateSession(testTerminalId);

      const session = await getSession(testTerminalId);
      expect(session?.active).toBe(false);
      expect(session?.socketId).toBeNull();
    });
  });

  describe('deleteSession', () => {
    it('should delete session from database', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      await deleteSession(testTerminalId);

      const session = await getSession(testTerminalId);
      expect(session).toBeNull();
    });

    it('should not throw for non-existent session', async () => {
      await expect(deleteSession('non-existent')).resolves.not.toThrow();
    });
  });

  describe('updateSessionSocket', () => {
    it('should update socket ID', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
        socketId: 'socket-old',
      });

      await updateSessionSocket(testTerminalId, 'socket-new');

      const session = await getSession(testTerminalId);
      expect(session?.socketId).toBe('socket-new');
    });

    it('should clear socket ID when null', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
        socketId: 'socket-123',
      });

      await updateSessionSocket(testTerminalId, null);

      const session = await getSession(testTerminalId);
      expect(session?.socketId).toBeNull();
    });
  });

  describe('cleanupOldSessions', () => {
    it('should delete inactive sessions older than specified hours', async () => {
      // Create an inactive session
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      await deactivateSession(testTerminalId);

      // Update lastActivityAt to 25 hours ago
      await prisma.session.update({
        where: { terminalId: testTerminalId },
        data: {
          lastActivityAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
        },
      });

      const count = await cleanupOldSessions(24);

      expect(count).toBe(1);

      const session = await getSession(testTerminalId);
      expect(session).toBeNull();
    });

    it('should not delete recent inactive sessions', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      await deactivateSession(testTerminalId);

      const count = await cleanupOldSessions(24);

      expect(count).toBe(0);

      const session = await getSession(testTerminalId);
      expect(session).toBeDefined();
    });

    it('should not delete active sessions regardless of age', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      // Update lastActivityAt to 25 hours ago but keep active
      await prisma.session.update({
        where: { terminalId: testTerminalId },
        data: {
          lastActivityAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
        },
      });

      const count = await cleanupOldSessions(24);

      expect(count).toBe(0);

      const session = await getSession(testTerminalId);
      expect(session).toBeDefined();
      expect(session?.active).toBe(true);
    });

    it('should delete expired sessions', async () => {
      await createTerminalSession({
        terminalId: testTerminalId,
        userId: testUserId,
        shell: '/bin/bash',
        cwd: '/home/user',
        cols: 80,
        rows: 24,
      });

      // Set expiration to past
      await prisma.session.update({
        where: { terminalId: testTerminalId },
        data: {
          expiresAt: new Date(Date.now() - 1000),
        },
      });

      const count = await cleanupOldSessions(24);

      expect(count).toBe(1);

      const session = await getSession(testTerminalId);
      expect(session).toBeNull();
    });
  });
});
