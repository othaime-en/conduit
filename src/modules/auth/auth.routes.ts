// src/modules/auth/auth.routes.ts

import { Router, Request, Response, NextFunction } from 'express';
import { AuthService } from './auth.service';
import {
    registerSchema,
    loginSchema,
    refreshTokenSchema,
    validate,
} from './auth.validation';
import { authenticate } from '@shared/middleware/auth.middleware';
import { logger } from '@shared/utils/logger';

const router = Router();
const authService = new AuthService();

/**
 * POST /auth/register
 * Register a new user
 */
router.post(
    '/register',
    validate(registerSchema),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const ipAddress = req.ip || req.socket.remoteAddress;
            const userAgent = req.headers['user-agent'];

            const tokens = await authService.register(req.body, ipAddress, userAgent);

            res.status(201).json({
                message: 'User registered successfully',
                ...tokens,
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * POST /auth/login
 * Login an existing user
 */
router.post(
    '/login',
    validate(loginSchema),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const ipAddress = req.ip || req.socket.remoteAddress;
            const userAgent = req.headers['user-agent'];

            const tokens = await authService.login(req.body, ipAddress, userAgent);

            res.status(200).json({
                message: 'Login successful',
                ...tokens,
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * POST /auth/refresh
 * Refresh access token using refresh token
 */
router.post(
    '/refresh',
    validate(refreshTokenSchema),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const ipAddress = req.ip || req.socket.remoteAddress;

            const tokens = await authService.refreshAccessToken(req.body, ipAddress);

            res.status(200).json({
                message: 'Token refreshed successfully',
                ...tokens,
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * POST /auth/logout
 * Logout user and revoke refresh token
 */
router.post(
    '/logout',
    validate(refreshTokenSchema),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            await authService.logout(req.body.refreshToken);

            res.status(200).json({
                message: 'Logout successful',
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * GET /auth/me
 * Get current user information (protected route)
 */
router.get(
    '/me',
    authenticate,
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            if (!req.user) {
                throw new Error('User not found in request');
            }

            const user = await authService.getUserById(req.user.userId);

            res.status(200).json({
                user,
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * GET /auth/health
 * Health check endpoint (public)
 */
router.get('/health', (req: Request, res: Response): void => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
    });
});

export default router;