import { Router, Response } from 'express';
import { sessionRecording } from '../lib/sessionRecording.js';
import { AuthenticatedRequest } from '../middleware/rbac.js';
import logger from '../config/logger.js';

const router = Router();

/**
 * POST /api/recordings/start
 * Start recording a terminal session
 */
router.post('/start', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId, title } = req.body;

    if (!terminalId) {
      return res.status(400).json({ error: 'Terminal ID is required' });
    }

    if (sessionRecording.isRecording(terminalId)) {
      return res.status(409).json({ error: 'Recording already in progress for this terminal' });
    }

    sessionRecording.startRecording(terminalId, req.user.userId, title);

    logger.info('Recording started', { terminalId, userId: req.user.userId });

    return res.status(200).json({
      success: true,
      message: 'Recording started',
      terminalId,
    });
  } catch (error) {
    logger.error('Start recording error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/recordings/stop
 * Stop recording a terminal session
 */
router.post('/stop', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId } = req.body;

    if (!terminalId) {
      return res.status(400).json({ error: 'Terminal ID is required' });
    }

    const filename = await sessionRecording.stopRecording(terminalId);

    if (!filename) {
      return res.status(404).json({ error: 'No recording found for this terminal' });
    }

    logger.info('Recording stopped', { terminalId, filename, userId: req.user.userId });

    return res.status(200).json({
      success: true,
      message: 'Recording stopped and saved',
      filename,
    });
  } catch (error) {
    logger.error('Stop recording error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/recordings
 * Get all recordings for the current user
 */
router.get('/', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const recordings = await sessionRecording.listUserRecordings(req.user.userId);

    return res.status(200).json({
      success: true,
      recordings,
    });
  } catch (error) {
    logger.error('List recordings error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/recordings/:filename
 * Get a specific recording
 */
router.get('/:filename', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { filename } = req.params;

    const recording = await sessionRecording.loadRecording(filename);

    if (!recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }

    // Check if user owns this recording (or is admin)
    if (recording.metadata.userId !== req.user.userId && req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied' });
    }

    return res.status(200).json({
      success: true,
      recording,
    });
  } catch (error) {
    logger.error('Get recording error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /api/recordings/:filename
 * Delete a recording
 */
router.delete('/:filename', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { filename } = req.params;

    // Check ownership
    const metadata = await sessionRecording.getRecordingMetadata(filename);
    if (!metadata) {
      return res.status(404).json({ error: 'Recording not found' });
    }

    if (metadata.userId !== req.user.userId && req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const deleted = await sessionRecording.deleteRecording(filename);

    if (!deleted) {
      return res.status(500).json({ error: 'Failed to delete recording' });
    }

    logger.info('Recording deleted', { filename, userId: req.user.userId });

    return res.status(200).json({
      success: true,
      message: 'Recording deleted',
    });
  } catch (error) {
    logger.error('Delete recording error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/recordings/:filename/export/asciicast
 * Export recording to asciicast format
 */
router.get('/:filename/export/asciicast', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { filename } = req.params;

    // Check ownership
    const metadata = await sessionRecording.getRecordingMetadata(filename);
    if (!metadata) {
      return res.status(404).json({ error: 'Recording not found' });
    }

    if (metadata.userId !== req.user.userId && req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const asciicastFilename = await sessionRecording.exportToAsciicast(filename);

    if (!asciicastFilename) {
      return res.status(500).json({ error: 'Failed to export recording' });
    }

    logger.info('Recording exported to asciicast', {
      filename,
      asciicastFilename,
      userId: req.user.userId,
    });

    return res.status(200).json({
      success: true,
      filename: asciicastFilename,
      message: 'Recording exported to asciicast format',
    });
  } catch (error) {
    logger.error('Export recording error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/recordings/:terminalId/status
 * Get recording status for a terminal
 */
router.get('/:terminalId/status', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId } = req.params;
    const isRecording = sessionRecording.isRecording(terminalId);
    const stats = sessionRecording.getRecordingStats(terminalId);

    return res.status(200).json({
      success: true,
      isRecording,
      stats,
    });
  } catch (error) {
    logger.error('Get recording status error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
