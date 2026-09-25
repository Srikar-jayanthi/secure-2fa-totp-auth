import express from 'express';
import cors from 'cors';
import { authRouter } from './routes/auth.js';
import { requireFullAuth } from './auth.js';

export const app = express();

app.use(cors());
app.use(express.json());

// Health check endpoints for Docker & monitoring
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Authentication endpoints
app.use('/api/auth', authRouter);

// General protected resource test endpoint
app.get('/api/protected', requireFullAuth, (req, res) => {
  res.status(200).json({
    message: 'Access granted to protected route',
    user: {
      id: req.user.userId,
      email: req.user.email,
    },
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error('Unhandled application error:', err);
  const status = err.status || 500;
  res.status(status).json({
    error: err.message || 'Internal server error',
  });
});
