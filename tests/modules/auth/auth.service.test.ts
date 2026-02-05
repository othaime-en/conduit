import 'dotenv/config';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { AuthService } from '../../../src/modules/auth/auth.service';
import pool from '../../../src/database/client';

describe('AuthService', () => {
    const authService = new AuthService();
    const createdUserIds: string[] = [];

    const generateEmail = () => `test-${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`;

    beforeAll(async () => {
        // Ensure test database is set up
        await pool.query('SELECT NOW()');
    });

    afterAll(async () => {
        // Clean up test data
        if (createdUserIds.length > 0) {
            await pool.query('DELETE FROM users WHERE id = ANY($1)', [createdUserIds]);
        }
        // Do not close pool as it might be shared or needed by other tests in parallel execution
        // await pool.end();
    });

    describe('register', () => {
        it('should register a new user successfully', async () => {
            const email = generateEmail();
            const result = await authService.register({
                email,
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
                [email]
            );
            createdUserIds.push(userResult.rows[0].id);
        });

        it('should reject registration with weak password', async () => {
            const email = generateEmail();
            await expect(
                authService.register({
                    email,
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
            const email = generateEmail();
            // Register first user
            await authService.register({
                email,
                password: 'Test123!@#',
            });

            // Get ID for cleanup
            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );
            createdUserIds.push(userResult.rows[0].id);

            // Try to register again with same email
            await expect(
                authService.register({
                    email,
                    password: 'Test123!@#',
                })
            ).rejects.toThrow('Email already registered');
        });
    });

    describe('login', () => {
        let testEmail: string;

        beforeEach(async () => {
            testEmail = generateEmail();
            // Create a test user
            await authService.register({
                email: testEmail,
                password: 'Test123!@#',
            });

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [testEmail]
            );
            createdUserIds.push(userResult.rows[0].id);
        });

        it('should login successfully with correct credentials', async () => {
            const result = await authService.login({
                email: testEmail,
                password: 'Test123!@#',
            });

            expect(result).toHaveProperty('accessToken');
            expect(result).toHaveProperty('refreshToken');
            expect(result).toHaveProperty('expiresIn');
        });

        it('should reject login with wrong password', async () => {
            await expect(
                authService.login({
                    email: testEmail,
                    password: 'WrongPassword123!',
                })
            ).rejects.toThrow('Invalid email or password');
        });

        it('should reject login with non-existent email', async () => {
            await expect(
                authService.login({
                    email: 'nonexistent-' + generateEmail(),
                    password: 'Test123!@#',
                })
            ).rejects.toThrow('Invalid email or password');
        });
    });

    describe('refreshAccessToken', () => {
        let refreshToken: string;
        let testEmail: string;

        beforeEach(async () => {
            testEmail = generateEmail();
            // Register and get refresh token
            const result = await authService.register({
                email: testEmail,
                password: 'Test123!@#',
            });
            refreshToken = result.refreshToken;

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [testEmail]
            );
            createdUserIds.push(userResult.rows[0].id);
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
        let testUserId: string;
        let testEmail: string;

        beforeEach(async () => {
            testEmail = generateEmail();
            // Create a test user
            await authService.register({
                email: testEmail,
                password: 'Test123!@#',
            });

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [testEmail]
            );
            testUserId = userResult.rows[0].id;
            createdUserIds.push(testUserId);
        });

        it('should get user by ID successfully', async () => {
            const user = await authService.getUserById(testUserId);

            expect(user).toHaveProperty('id');
            expect(user).toHaveProperty('email');
            expect(user.email).toBe(testEmail);
            expect(user).not.toHaveProperty('password_hash');
        });

        it('should throw error for non-existent user', async () => {
            await expect(
                authService.getUserById('00000000-0000-0000-0000-000000000000')
            ).rejects.toThrow('User not found');
        });
    });
});
