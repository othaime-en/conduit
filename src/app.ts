import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { errorHandler } from './shared/middleware/error.middleware';
import { logger } from './shared/utils/logger';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
}));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`);
    next();
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    });
});

// API routes (will add in later phases)
// app.use('/api', routes);

// Error handling
app.use(errorHandler);

export default app;