import 'dotenv/config';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import pool from '../../../src/database/client';

describe('Auth API Routes', () => {
    let accessToken: string;
    let refreshToken: string;
    const createdUserIds: string[] = [];

    const generateEmail = () => `test-route-${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`;

    beforeAll(async () => {
        await pool.query('SELECT NOW()');
    });

    afterAll(async () => {
        if (createdUserIds.length > 0) {
            await pool.query('DELETE FROM users WHERE id = ANY($1)', [createdUserIds]);
        }
    });

    describe('POST /api/auth/register', () => {
        it('should register a new user', async () => {
            const email = generateEmail();
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email,
                    password: 'Test123!@#',
                })
                .expect(201);

            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');
            expect(response.body).toHaveProperty('message', 'User registered successfully');

            // Save tokens and user ID for other tests if needed (though scoped here)
            accessToken = response.body.accessToken;
            refreshToken = response.body.refreshToken;

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );
            createdUserIds.push(userResult.rows[0].id);
        });

        it('should return 400 for invalid email', async () => {
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: 'invalid-email',
                    password: 'Test123!@#',
                })
                .expect(400);

            expect(response.body).toHaveProperty('error');
        });

        it('should return 400 for weak password', async () => {
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: generateEmail(),
                    password: 'weak',
                })
                .expect(400);

            expect(response.body).toHaveProperty('error');
        });

        it('should return 400 for duplicate email', async () => {
            const email = generateEmail();
            // Register first user
            await request(app)
                .post('/api/auth/register')
                .send({
                    email,
                    password: 'Test123!@#',
                })
                .expect(201);

            // Get ID for cleanup
            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );
            createdUserIds.push(userResult.rows[0].id);

            // Try to register again
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email,
                    password: 'Test123!@#',
                })
                .expect(400);

            expect(response.body.error).toContain('already registered');
        });
    });

    describe('POST /api/auth/login', () => {
        let testEmail: string;

        beforeEach(async () => {
            testEmail = generateEmail();
            // Create a user first
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: testEmail,
                    password: 'Test123!@#',
                });

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [testEmail]
            );
            createdUserIds.push(userResult.rows[0].id);
        });

        it('should login successfully', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testEmail,
                    password: 'Test123!@#',
                })
                .expect(200);

            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');
            expect(response.body).toHaveProperty('message', 'Login successful');
        });

        it('should return 401 for wrong password', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testEmail,
                    password: 'WrongPassword123!',
                })
                .expect(401);

            expect(response.body.error).toContain('Invalid email or password');
        });

        it('should return 401 for non-existent user', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'nonexistent-' + generateEmail(),
                    password: 'Test123!@#',
                })
                .expect(401);

            expect(response.body.error).toContain('Invalid email or password');
        });
    });

    describe('GET /api/auth/me', () => {
        let testEmail: string;

        beforeEach(async () => {
            testEmail = generateEmail();
            // Register and login
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: testEmail,
                    password: 'Test123!@#',
                });

            accessToken = response.body.accessToken;

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [testEmail]
            );
            createdUserIds.push(userResult.rows[0].id);
        });

        it('should get current user with valid token', async () => {
            const response = await request(app)
                .get('/api/auth/me')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(response.body.user).toHaveProperty('id');
            expect(response.body.user).toHaveProperty('email', testEmail);
            expect(response.body.user).not.toHaveProperty('password_hash');
        });

        it('should return 401 without token', async () => {
            const response = await request(app)
                .get('/api/auth/me')
                .expect(401);

            expect(response.body.error).toContain('No authorization token provided');
        });

        it('should return 401 with invalid token', async () => {
            const response = await request(app)
                .get('/api/auth/me')
                .set('Authorization', 'Bearer invalid-token')
                .expect(401);

            expect(response.body.error).toContain('Invalid token');
        });
    });

    describe('POST /api/auth/refresh', () => {
        let testEmail: string;

        beforeEach(async () => {
            testEmail = generateEmail();
            // Register and get tokens
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: testEmail,
                    password: 'Test123!@#',
                });

            refreshToken = response.body.refreshToken;

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [testEmail]
            );
            createdUserIds.push(userResult.rows[0].id);
        });

        it('should refresh access token successfully', async () => {
            const response = await request(app)
                .post('/api/auth/refresh')
                .send({
                    refreshToken,
                })
                .expect(200);

            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');
            expect(response.body.accessToken).not.toBe(refreshToken);
        });

        it('should return 401 with invalid refresh token', async () => {
            const response = await request(app)
                .post('/api/auth/refresh')
                .send({
                    refreshToken: 'invalid-token',
                })
                .expect(401);

            expect(response.body.error).toBeDefined();
        });
    });

    describe('POST /api/auth/logout', () => {
        let testEmail: string;

        beforeEach(async () => {
            testEmail = generateEmail();
            // Register and get tokens
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: testEmail,
                    password: 'Test123!@#',
                });

            refreshToken = response.body.refreshToken;

            const userResult = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [testEmail]
            );
            createdUserIds.push(userResult.rows[0].id);
        });

        it('should logout successfully', async () => {
            const response = await request(app)
                .post('/api/auth/logout')
                .send({
                    refreshToken,
                })
                .expect(200);

            expect(response.body.message).toBe('Logout successful');
        });

        it('should not be able to use refresh token after logout', async () => {
            // Logout
            await request(app)
                .post('/api/auth/logout')
                .send({
                    refreshToken,
                })
                .expect(200);

            // Try to use the token
            const response = await request(app)
                .post('/api/auth/refresh')
                .send({
                    refreshToken,
                })
                .expect(401);

            expect(response.body.error).toContain('revoked');
        });
    });

    describe('GET /api/auth/health', () => {
        it('should return health status', async () => {
            const response = await request(app)
                .get('/api/auth/health')
                .expect(200);

            expect(response.body).toHaveProperty('status', 'healthy');
            expect(response.body).toHaveProperty('timestamp');
        });
    });
});
