import express,{ Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface AuthenticatedRequest extends Request {
    userId?: string;
  }

export const authenticate = (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) => {
    try {
      
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'not Authorization' });
      }
  
      const token = authHeader.split(' ')[1];
      if (!token) {
        return res.status(401).json({ error: 'DOesnt have token' });
      }
  
      const secretKey = process.env.JWT_SECRET || 'token';
      const decoded = jwt.verify(token, secretKey) as { userId: string };
  
      
      req.userId = decoded.userId;
  
      next();
    } catch (error) {
      console.error('Error authenticating:', error);
      res.status(401).json({ error: 'Invalid token' });
    }
  };