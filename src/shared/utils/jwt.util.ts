import jwt from 'jsonwebtoken';
import { JWTPayload } from '@modules/auth/auth.types';
import { UnauthorizedError } from './errors';

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'your-super-secret-jwt-key-change-in-production') {
    throw new Error('JWT_SECRET must be set in production environment');
}

// Define the payload type for token generation
type TokenPayload = Pick<JWTPayload, 'userId' | 'email'>;

/**
 * Generate an access token (short-lived)
 * @param payload - User data to encode in JWT
 * @returns JWT access token
 */
export function generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(
        payload as jwt.JwtPayload,
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN } as jwt.SignOptions
    );
}

/**
 * Generate a refresh token (long-lived)
 * @param payload - User data to encode in JWT
 * @returns JWT refresh token
 */
export function generateRefreshToken(payload: TokenPayload): string {
    return jwt.sign(
        payload as jwt.JwtPayload,
        JWT_SECRET,
        { expiresIn: JWT_REFRESH_EXPIRES_IN } as jwt.SignOptions
    );
}

/**
 * Verify and decode a JWT token
 * @param token - JWT token to verify
 * @returns Decoded JWT payload
 * @throws UnauthorizedError if token is invalid or expired
 */
export function verifyToken(token: string): JWTPayload {
    try {
        const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload;
        return decoded;
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new UnauthorizedError('Token expired');
        }
        if (error instanceof jwt.JsonWebTokenError) {
            throw new UnauthorizedError('Invalid token');
        }
        throw new UnauthorizedError('Token verification failed');
    }
}

/**
 * Decode a JWT token without verification (for debugging)
 * @param token - JWT token to decode
 * @returns Decoded JWT payload or null if invalid
 */
export function decodeToken(token: string): JWTPayload | null {
    try {
        return jwt.decode(token) as JWTPayload;
    } catch {
        return null;
    }
}

/**
 * Get token expiration time in seconds
 * @param expiresIn - Expiration string (e.g., '15m', '7d')
 * @returns Expiration time in seconds
 */
export function getExpirationSeconds(expiresIn: string = JWT_EXPIRES_IN): number {
    const unit = expiresIn.slice(-1);
    const value = parseInt(expiresIn.slice(0, -1), 10);

    switch (unit) {
        case 's':
            return value;
        case 'm':
            return value * 60;
        case 'h':
            return value * 60 * 60;
        case 'd':
            return value * 60 * 60 * 24;
        default:
            return 900; // Default 15 minutes
    }
}