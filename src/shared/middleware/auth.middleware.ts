import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '@shared/utils/jwt.util';
import { UnauthorizedError } from '@shared/utils/errors';
import { JWTPayload } from '@modules/auth/auth.types';

// Extend Express Request type to include user
declare global {
    namespace Express {
        interface Request {
            user?: JWTPayload;
        }
    }
}

/**
 * Middleware to authenticate requests using JWT
 * Expects Authorization header with Bearer token
 */
export const authenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        // Get token from Authorization header
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            throw new UnauthorizedError('No authorization token provided');
        }

        // Check if it's a Bearer token
        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0] !== 'Bearer') {
            throw new UnauthorizedError('Invalid authorization format. Use: Bearer <token>');
        }

        const token = parts[1];

        // Verify and decode token
        const payload = verifyToken(token);

        // Attach user to request
        req.user = payload;

        next();
    } catch (error) {
        next(error);
    }
};

/**
 * Optional authentication - doesn't fail if no token provided
 * Useful for routes that work differently for authenticated vs anonymous users
 */
export const optionalAuthenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const authHeader = req.headers.authorization;

        if (authHeader) {
            const parts = authHeader.split(' ');
            if (parts.length === 2 && parts[0] === 'Bearer') {
                const token = parts[1];
                const payload = verifyToken(token);
                req.user = payload;
            }
        }

        next();
    } catch (error) {
        // Don't fail on optional auth errors
        next();
    }
};