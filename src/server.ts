import dotenv from 'dotenv';
dotenv.config();

import app from './app';
import { logger } from './shared/utils/logger';

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV}`);
});