import { Request, Response, NextFunction } from 'express';
import { AppError } from '@shared/utils/errors';
import { logger } from '@shared/utils/logger';

/**
 * Global error handler middleware
 * Catches all errors and formats them consistently
 */
export const errorHandler = (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    // Log error
    logger.error('Error occurred:', {
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        ip: req.ip,
    });

    // Handle AppError (our custom errors)
    if (err instanceof AppError) {
        res.status(err.statusCode).json({
            error: err.message,
            statusCode: err.statusCode,
        });
        return;
    }

    // Handle other known errors
    if (err.name === 'ValidationError') {
        res.status(400).json({
            error: err.message,
            statusCode: 400,
        });
        return;
    }

    // Handle PostgreSQL errors
    if (err.name === 'DatabaseError' || (err as any).code) {
        const pgError = err as any;

        // Unique constraint violation
        if (pgError.code === '23505') {
            res.status(409).json({
                error: 'Resource already exists',
                statusCode: 409,
            });
            return;
        }

        // Foreign key violation
        if (pgError.code === '23503') {
            res.status(400).json({
                error: 'Invalid reference',
                statusCode: 400,
            });
            return;
        }

        // Generic database error (don't expose details in production)
        res.status(500).json({
            error: process.env.NODE_ENV === 'production'
                ? 'Database error occurred'
                : pgError.message,
            statusCode: 500,
        });
        return;
    }

    // Default to 500 server error
    res.status(500).json({
        error: process.env.NODE_ENV === 'production'
            ? 'Internal server error'
            : err.message,
        statusCode: 500,
    });
};

/**
 * 404 Not Found handler
 * Place this after all routes
 */
export const notFoundHandler = (
    req: Request,
    res: Response
): void => {
    res.status(404).json({
        error: `Route ${req.method} ${req.path} not found`,
        statusCode: 404,
    });
};

/**
 * Async handler wrapper
 * Wraps async route handlers to catch errors automatically
 */
export const asyncHandler = (fn: Function) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};