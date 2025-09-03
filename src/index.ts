import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import { authRouter } from './routes/auth';
import { keysRouter } from './routes/keys';
import { errorHandler } from './middleware/errorHandler';
import { validateApiKey } from './middleware/auth';
import { keyRetrievalLimiter, authLimiter, securityHeaders } from './middleware/security';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true,
}));
app.use(express.json());
app.use(limiter);
app.use(securityHeaders);

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.use('/api/auth', authLimiter, authRouter);
app.use('/api/keys', validateApiKey, keyRetrievalLimiter, keysRouter);

app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Key server running on port ${PORT}`);
});