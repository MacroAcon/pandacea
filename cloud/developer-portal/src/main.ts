import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import { developerRouter } from './routes/developer';
import { queryRouter } from './routes/query';
import { analyticsRouter } from './routes/analytics';
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';
import { rateLimiter } from './middleware/rateLimiter';
import { apiKeyAuth } from './middleware/apiKeyAuth';

// Load environment variables
config();

const app = express();
const port = process.env.PORT || 3003;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(rateLimiter);
app.use(apiKeyAuth);

// Routes
app.use('/developers', developerRouter);
app.use('/queries', queryRouter);
app.use('/analytics', analyticsRouter);

// Error handling
app.use(errorHandler);

// Start server
app.listen(port, () => {
    logger.info(`Developer Portal API running on port ${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    // TODO: Close database connections, etc.
    process.exit(0);
}); 