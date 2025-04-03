import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import { deviceRouter } from './routes/device';
import { queryRouter } from './routes/query';
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';
import { WebSocketServer } from 'ws';
import { handleWebSocketConnection } from './websocket/handler';

// Load environment variables
config();

const app = express();
const port = process.env.PORT || 3001;
const wsPort = process.env.WS_PORT || 8080;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/devices', deviceRouter);
app.use('/queries', queryRouter);

// Error handling
app.use(errorHandler);

// WebSocket server
const wss = new WebSocketServer({ port: wsPort });
wss.on('connection', handleWebSocketConnection);

// Start HTTP server
app.listen(port, () => {
    logger.info(`Device Registry running on port ${port}`);
    logger.info(`WebSocket server running on port ${wsPort}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    wss.close(() => {
        logger.info('WebSocket server closed');
        // TODO: Close database connections, etc.
        process.exit(0);
    });
}); 