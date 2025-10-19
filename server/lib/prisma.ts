import { PrismaClient } from '@prisma/client';
import logger from '../config/logger.js';

// Create a single instance of Prisma Client
const prisma = new PrismaClient({
  log: [
    { level: 'warn', emit: 'event' },
    { level: 'error', emit: 'event' },
  ],
});

// Log Prisma warnings and errors using our logger
prisma.$on('warn' as never, (e: { message: string }) => {
  logger.warn('Prisma warning', { message: e.message });
});

prisma.$on('error' as never, (e: { message: string }) => {
  logger.error('Prisma error', { message: e.message });
});

// Export both default and named export for flexibility
export { prisma };
export default prisma;
