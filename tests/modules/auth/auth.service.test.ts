import 'dotenv/config';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { AuthService } from '../../../src/modules/auth/auth.service';
import pool from '../../../src/database/client';

describe('AuthService', () => {
    const authService = new AuthService();
    let testUserId: string;

    beforeAll(async () => {
        // Ensure test database is set up
        await pool.query('SELECT NOW()');
    });

    afterAll(async () => {
        // Clean up test data
        if (testUserId) {
            await pool.query('DELETE FROM users WHERE id = $1', [testUserId]);
        }
        await pool.end();
    });

    beforeEach(async () => {
        // Clean up any existing test user
        await pool.query('DELETE FROM users WHERE email = $1', ['test@example.com']);
    });

    describe('register', () => {
        it('should register a new user successfully', async () => {
            const result = await authService.register({
                email: 'test@example.com',
                password: 'Test123!@#',
            });

            expect(result).toHaveProperty('accessToken');
            expect(result).toHaveProperty('refreshToken');
            expect(result).toHaveProperty('expiresIn');
            expect(typeof result.accessToken).toBe('string');
            expect(typeof result.refreshToken).toBe('string');

            // Save user ID for cleanup
            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                ['test@example.com']
            );
            testUserId = userResult.rows[0].id;
        });

        it('should reject registration with weak password', async () => {
            await expect(
                authService.register({
                    email: 'test@example.com',
                    password: 'weak',
                })
            ).rejects.toThrow();
        });

        it('should reject registration with invalid email', async () => {
            await expect(
                authService.register({
                    email: 'invalid-email',
                    password: 'Test123!@#',
                })
            ).rejects.toThrow('Invalid email format');
        });

        it('should reject duplicate email registration', async () => {
            // Register first user
            await authService.register({
                email: 'test@example.com',
                password: 'Test123!@#',
            });

            // Try to register again with same email
            await expect(
                authService.register({
                    email: 'test@example.com',
                    password: 'Test123!@#',
                })
            ).rejects.toThrow('Email already registered');
        });
    });

    describe('login', () => {
        beforeEach(async () => {
            // Create a test user
            await authService.register({
                email: 'test@example.com',
                password: 'Test123!@#',
            });

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                ['test@example.com']
            );
            testUserId = userResult.rows[0].id;
        });

        it('should login successfully with correct credentials', async () => {
            const result = await authService.login({
                email: 'test@example.com',
                password: 'Test123!@#',
            });

            expect(result).toHaveProperty('accessToken');
            expect(result).toHaveProperty('refreshToken');
            expect(result).toHaveProperty('expiresIn');
        });

        it('should reject login with wrong password', async () => {
            await expect(
                authService.login({
                    email: 'test@example.com',
                    password: 'WrongPassword123!',
                })
            ).rejects.toThrow('Invalid email or password');
        });

        it('should reject login with non-existent email', async () => {
            await expect(
                authService.login({
                    email: 'nonexistent@example.com',
                    password: 'Test123!@#',
                })
            ).rejects.toThrow('Invalid email or password');
        });
    });

    describe('refreshAccessToken', () => {
        let refreshToken: string;

        beforeEach(async () => {
            // Register and get refresh token
            const result = await authService.register({
                email: 'test@example.com',
                password: 'Test123!@#',
            });
            refreshToken = result.refreshToken;

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                ['test@example.com']
            );
            testUserId = userResult.rows[0].id;
        });

        it('should refresh access token successfully', async () => {
            const result = await authService.refreshAccessToken({
                refreshToken,
            });

            expect(result).toHaveProperty('accessToken');
            expect(result).toHaveProperty('refreshToken');
            expect(result.accessToken).not.toBe(refreshToken);
        });

        it('should reject invalid refresh token', async () => {
            await expect(
                authService.refreshAccessToken({
                    refreshToken: 'invalid-token',
                })
            ).rejects.toThrow();
        });
    });

    describe('getUserById', () => {
        beforeEach(async () => {
            // Create a test user
            await authService.register({
                email: 'test@example.com',
                password: 'Test123!@#',
            });

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                ['test@example.com']
            );
            testUserId = userResult.rows[0].id;
        });

        it('should get user by ID successfully', async () => {
            const user = await authService.getUserById(testUserId);

            expect(user).toHaveProperty('id');
            expect(user).toHaveProperty('email');
            expect(user.email).toBe('test@example.com');
            expect(user).not.toHaveProperty('password_hash');
        });

        it('should throw error for non-existent user', async () => {
            await expect(
                authService.getUserById('00000000-0000-0000-0000-000000000000')
            ).rejects.toThrow('User not found');
        });
    });
});