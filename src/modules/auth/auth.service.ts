import pool from '@database/client';
import {
    User,
    UserWithoutPassword,
    RegisterDTO,
    LoginDTO,
    AuthTokens,
    RefreshTokenDTO,
    JWTPayload,
} from './auth.types';
import { hashPassword, comparePassword, validatePasswordStrength } from '@shared/utils/password.util';
import {
    generateAccessToken,
    generateRefreshToken,
    verifyToken,
    getExpirationSeconds,
} from '@shared/utils/jwt.util';
import { generateRandomToken, hashToken } from '@shared/utils/encryption.util';
import { ValidationError, UnauthorizedError, NotFoundError } from '@shared/utils/errors';
import { logger } from '@shared/utils/logger';

export class AuthService {
    /**
     * Register a new user
     */
    async register(data: RegisterDTO, ipAddress?: string, userAgent?: string): Promise<AuthTokens> {
        const { email, password } = data;

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw new ValidationError('Invalid email format');
        }

        // Validate password strength
        const passwordValidation = validatePasswordStrength(password);
        if (!passwordValidation.valid) {
            throw new ValidationError(passwordValidation.errors.join(', '));
        }

        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (existingUser.rows.length > 0) {
            throw new ValidationError('Email already registered');
        }

        // Hash password
        const passwordHash = await hashPassword(password);

        // Generate email verification token
        const verificationToken = generateRandomToken();
        const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        // Create user
        const result = await pool.query(
            `INSERT INTO users (email, password_hash, verification_token, verification_token_expires_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       RETURNING id, email, email_verified, created_at, updated_at`,
            [email.toLowerCase(), passwordHash, verificationToken, verificationExpiry]
        );

        const user = result.rows[0];

        logger.info(`New user registered: ${user.id}`);

        // Generate tokens
        const tokens = await this.generateTokens(user.id, user.email, ipAddress, userAgent);

        // TODO: Send verification email (implement in Phase 5)
        // await this.sendVerificationEmail(user.email, verificationToken);

        return tokens;
    }

    /**
     * Login an existing user
     */
    async login(data: LoginDTO, ipAddress?: string, userAgent?: string): Promise<AuthTokens> {
        const { email, password } = data;

        // Find user by email
        const result = await pool.query(
            'SELECT id, email, password_hash, email_verified FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (result.rows.length === 0) {
            throw new UnauthorizedError('Invalid email or password');
        }

        const user = result.rows[0];

        // Compare password
        const isPasswordValid = await comparePassword(password, user.password_hash);
        if (!isPasswordValid) {
            throw new UnauthorizedError('Invalid email or password');
        }

        // Update last login timestamp
        await pool.query(
            'UPDATE users SET last_login_at = NOW() WHERE id = $1',
            [user.id]
        );

        logger.info(`User logged in: ${user.id}`);

        // Generate tokens
        return this.generateTokens(user.id, user.email, ipAddress, userAgent);
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshAccessToken(data: RefreshTokenDTO, ipAddress?: string): Promise<AuthTokens> {
        const { refreshToken } = data;

        // Verify refresh token
        let payload: JWTPayload;
        try {
            payload = verifyToken(refreshToken);
        } catch (error) {
            throw new UnauthorizedError('Invalid or expired refresh token');
        }

        // Check if refresh token exists in database and is not revoked
        const tokenHash = hashToken(refreshToken);
        const result = await pool.query(
            `SELECT id, user_id, expires_at, revoked_at 
       FROM refresh_tokens 
       WHERE token_hash = $1`,
            [tokenHash]
        );

        if (result.rows.length === 0) {
            throw new UnauthorizedError('Refresh token not found');
        }

        const storedToken = result.rows[0];

        if (storedToken.revoked_at) {
            throw new UnauthorizedError('Refresh token has been revoked');
        }

        if (new Date(storedToken.expires_at) < new Date()) {
            throw new UnauthorizedError('Refresh token expired');
        }

        // Verify user still exists
        const userResult = await pool.query(
            'SELECT id, email FROM users WHERE id = $1',
            [storedToken.user_id]
        );

        if (userResult.rows.length === 0) {
            throw new UnauthorizedError('User not found');
        }

        const user = userResult.rows[0];

        // Generate new tokens
        const newTokens = await this.generateTokens(user.id, user.email, ipAddress);

        // Revoke old refresh token
        await this.revokeRefreshToken(tokenHash);

        logger.info(`Access token refreshed for user: ${user.id}`);

        return newTokens;
    }

    /**
     * Logout user by revoking refresh token
     */
    async logout(refreshToken: string): Promise<void> {
        const tokenHash = hashToken(refreshToken);
        await this.revokeRefreshToken(tokenHash);
        logger.info('User logged out, refresh token revoked');
    }

    /**
     * Get user by ID (without password)
     */
    async getUserById(userId: string): Promise<UserWithoutPassword> {
        const result = await pool.query(
            `SELECT id, email, email_verified, created_at, updated_at, last_login_at 
       FROM users 
       WHERE id = $1`,
            [userId]
        );

        if (result.rows.length === 0) {
            throw new NotFoundError('User not found');
        }

        return result.rows[0];
    }

    /**
     * Generate access and refresh tokens
     */
    private async generateTokens(
        userId: string,
        email: string,
        ipAddress?: string,
        userAgent?: string
    ): Promise<AuthTokens> {
        const payload: Omit<JWTPayload, 'iat' | 'exp'> = {
            userId,
            email,
        };

        const accessToken = generateAccessToken(payload);
        const refreshToken = generateRefreshToken(payload);

        // Store refresh token in database
        const tokenHash = hashToken(refreshToken);
        const expiresAt = new Date(Date.now() + getExpirationSeconds(process.env.JWT_REFRESH_EXPIRES_IN!) * 1000);

        await pool.query(
            `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
            [userId, tokenHash, expiresAt, ipAddress, userAgent]
        );

        return {
            accessToken,
            refreshToken,
            expiresIn: getExpirationSeconds(),
        };
    }

    /**
     * Revoke a refresh token
     */
    private async revokeRefreshToken(tokenHash: string): Promise<void> {
        await pool.query(
            'UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1',
            [tokenHash]
        );
    }

    /**
     * Clean up expired refresh tokens (run periodically)
     */
    async cleanupExpiredTokens(): Promise<number> {
        const result = await pool.query(
            'DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked_at < NOW() - INTERVAL \'30 days\''
        );

        logger.info(`Cleaned up ${result.rowCount} expired refresh tokens`);
        return result.rowCount || 0;
    }
}