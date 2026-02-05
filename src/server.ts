import dotenv from 'dotenv';
import app from './app';
import pool from '@database/client';
import { logger } from '@shared/utils/logger';

dotenv.config();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

/**
 * Start the server
 */
async function startServer() {
    try {
        // Test database connection
        await pool.query('SELECT NOW()');
        logger.info('✅ Database connected successfully');

        // Start HTTP server
        app.listen(PORT, () => {
            logger.info(`🚀 Server running on port ${PORT}`);
            logger.info(`📦 Environment: ${NODE_ENV}`);
            logger.info(`🔗 API: http://localhost:${PORT}`);
        });
    } catch (error) {
        logger.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

/**
 * Graceful shutdown
 */
process.on('SIGTERM', async () => {
    logger.info('SIGTERM received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    logger.info('SIGINT received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // In production, you might want to restart the process
});

startServer();