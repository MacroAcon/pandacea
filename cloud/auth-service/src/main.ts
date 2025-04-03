import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import { authRouter } from './routes/auth';
import { userRouter } from './routes/user';
import { developerRouter } from './routes/developer';
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';

// Load environment variables
config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/auth', authRouter);
app.use('/users', userRouter);
app.use('/developers', developerRouter);

// Error handling
app.use(errorHandler);

// Start server
app.listen(port, () => {
    logger.info(`Authentication Service running on port ${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    // TODO: Close database connections, etc.
    process.exit(0);
}); 