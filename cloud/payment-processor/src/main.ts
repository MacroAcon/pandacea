import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import { paymentRouter } from './routes/payment';
import { earningsRouter } from './routes/earnings';
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';
import { processPendingPayments } from './services/paymentProcessor';

// Load environment variables
config();

const app = express();
const port = process.env.PORT || 3002;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/payments', paymentRouter);
app.use('/earnings', earningsRouter);

// Error handling
app.use(errorHandler);

// Start payment processing job
const paymentProcessingInterval = setInterval(async () => {
    try {
        await processPendingPayments();
    } catch (error) {
        logger.error('Error processing payments:', error);
    }
}, 5 * 60 * 1000); // Run every 5 minutes

// Start server
app.listen(port, () => {
    logger.info(`Payment Processor running on port ${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    clearInterval(paymentProcessingInterval);
    // TODO: Close database connections, etc.
    process.exit(0);
}); 