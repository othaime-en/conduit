import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
    plugins: [tsconfigPaths()], // This automatically loads paths from tsconfig.json
    test: {
        globals: true, // Optional: allows using describe, it, expect without imports
        environment: 'node', // Important for backend apps
    },
});