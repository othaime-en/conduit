import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/errors';
import { logger } from '../utils/logger';

export const errorHandler = (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    if (err instanceof AppError) {
        logger.error({
            message: err.message,
            statusCode: err.statusCode,
            stack: err.stack,
        });

        return res.status(err.statusCode).json({
            status: 'error',
            message: err.message,
        });
    }

    logger.error({
        message: err.message,
        stack: err.stack,
    });

    res.status(500).json({
        status: 'error',
        message: 'Internal server error',
    });
};