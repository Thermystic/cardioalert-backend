import jwt from 'jsonwebtoken';
import { config } from '../config/env';

export interface JwtPayload {
  userId: string;
  email: string;
  role: string;
}

export const generateToken = (payload: JwtPayload): string => {
  return jwt.sign(payload, config.jwtSecret, { expiresIn: '24h' });
};

export const verifyToken = (token: string): JwtPayload => {
  return jwt.verify(token, config.jwtSecret) as JwtPayload;
};
