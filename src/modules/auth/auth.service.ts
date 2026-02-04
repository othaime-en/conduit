import pool from '@database/client';
import {
    RegisterDTO,
    LoginDTO,
    AuthTokens,
    JWTPayload,
} from './auth.types';
import { hashPassword, comparePassword, validatePasswordStrength } from '@shared/utils/password.util';
import {
    generateAccessToken,
    generateRefreshToken,
    getExpirationSeconds,
} from '@shared/utils/jwt.util';
import { generateRandomToken, hashToken } from '@shared/utils/encryption.util';
import { ValidationError, UnauthorizedError } from '@shared/utils/errors';
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

        // TODO: Send verification email (implement later (Phase 5))
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
}