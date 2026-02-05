import { describe, it, expect } from 'vitest';
import request from 'supertest';
import app from '../src/app';

describe('Application Setup', () => {
    it('should return health check', async () => {
        const response = await request(app).get('/health');
        expect(response.status).toBe(200);
        expect(response.body.status).toBe('healthy');
    });

    it('should handle 404 errors', async () => {
        const response = await request(app).get('/nonexistent');
        expect(response.status).toBe(404);
    });
});