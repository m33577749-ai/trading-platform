import express from 'express';
import bcrypt from 'bcryptjs';
import { body, validationResult } from 'express-validator';
import { query } from '../config/database.js';
import { authenticate } from '../middleware/auth.js';
import { generateAccessToken, generateRefreshToken } from '../utils/tokenManager.js';
import { isValidEmail, isValidPassword, isValidUsername } from '../utils/validators.js';
import { logger } from '../utils/logger.js';
import { createAuditLog } from '../services/auditLogService.js';

const router = express.Router();

// ============================================
// POST /api/auth/register - التسجيل
// ============================================
router.post(
  '/register',
  [
    body('email').isEmail().normalizeEmail(),
    body('username').isLength({ min: 3, max: 20 }),
    body('password').isLength({ min: 8 }),
    body('firstName').isLength({ min: 2 }),
    body('lastName').isLength({ min: 2 }),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array(),
        });
      }

      const { email, username, password, firstName, lastName } = req.body;

      // التحقق من صحة البريد الإلكتروني
      if (!isValidEmail(email)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid email format',
        });
      }

      // التحقق من صحة كلمة المرور
      if (!isValidPassword(password)) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character',
        });
      }

      // التحقق من صحة اسم المستخدم
      if (!isValidUsername(username)) {
        return res.status(400).json({
          success: false,
          message: 'Username must be 3-20 characters, alphanumeric and underscore only',
        });
      }

      // البحث عن بريد إلكتروني موجود
      const emailExists = await query(
        'SELECT id FROM users WHERE email = $1',
        [email]
      );

      if (emailExists.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Email already registered',
        });
      }

      // البحث عن اسم مستخدم موجود
      const usernameExists = await query(
        'SELECT id FROM users WHERE username = $1',
        [username]
      );

      if (usernameExists.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Username already taken',
        });
      }

      // تجزئة كلمة المرور
      const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 10);

      // إنشاء المستخدم الجديد
      const result = await query(
        `INSERT INTO users (email, username, password_hash, first_name, last_name, role, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, email, username, first_name, last_name, role, created_at`,
        [email, username, hashedPassword, firstName, lastName, 'user', 'active']
      );

      const user = result.rows[0];

      // تسجيل العملية
      await createAuditLog({
        userId: user.id,
        action: 'USER_REGISTERED',
        resourceType: 'user',
        resourceId: user.id,
        ipAddress: req.ip,
      });

      // إنشاء محفظة افتراضية للمستخدم
      await query(
        `INSERT INTO wallets (user_id, currency, balance)
         VALUES ($1, $2, $3)`,
        [user.id, 'USD', 0]
      );

      logger.info({
        message: 'New user registered',
        userId: user.id,
        email: user.email,
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
          createdAt: user.created_at,
        },
      });
    } catch (error) {
      logger.error({
        message: 'Registration error',
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
);

// ============================================
// POST /api/auth/login - تسجيل الدخول
// ============================================
router.post(
  '/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array(),
        });
      }

      const { email, password } = req.body;

      // البحث عن المستخدم
      const result = await query(
        `SELECT id, email, username, password_hash, first_name, last_name, role, status, failed_login_attempts, locked_until
         FROM users WHERE email = $1`,
        [email]
      );

      if (result.rows.length === 0) {
        logger.warn({
          message: 'Login attempt with non-existent email',
          email,
          ip: req.ip,
        });
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password',
        });
      }

      const user = result.rows[0];

      // التحقق من قفل الحساب
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        logger.warn({
          message: 'Login attempt on locked account',
          userId: user.id,
          ip: req.ip,
        });
        return res.status(423).json({
          success: false,
          message: 'Account temporarily locked. Please try again later.',
        });
      }

      // التحقق ��ن حالة الحساب
      if (user.status !== 'active') {
        return res.status(403).json({
          success: false,
          message: 'Account is not active',
        });
      }

      // التحقق من كلمة المرور
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);

      if (!isPasswordValid) {
        // زيادة عدد محاولات تسجيل الدخول الفاشلة
        const newAttempts = (user.failed_login_attempts || 0) + 1;
        const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;

        if (newAttempts >= maxAttempts) {
          const lockTime = new Date(Date.now() + parseInt(process.env.LOCK_TIME_MINUTES) * 60000);
          await query(
            'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
            [newAttempts, lockTime, user.id]
          );

          logger.warn({
            message: 'Account locked due to failed login attempts',
            userId: user.id,
            attempts: newAttempts,
          });

          return res.status(423).json({
            success: false,
            message: 'Too many failed login attempts. Account locked.',
          });
        }

        await query(
          'UPDATE users SET failed_login_attempts = $1 WHERE id = $2',
          [newAttempts, user.id]
        );

        logger.warn({
          message: 'Failed login attempt',
          userId: user.id,
          attempts: newAttempts,
        });

        return res.status(401).json({
          success: false,
          message: 'Invalid email or password',
        });
      }

      // إعادة تعيين محاولات تسجيل الدخول الفاشلة
      await query(
        'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1',
        [user.id]
      );

      // إنشاء الرموز
      const accessToken = generateAccessToken(user.id, user.email, user.role);
      const refreshToken = generateRefreshToken(user.id);

      // تسجيل العملية
      await createAuditLog({
        userId: user.id,
        action: 'USER_LOGIN',
        resourceType: 'user',
        resourceId: user.id,
        ipAddress: req.ip,
      });

      logger.info({
        message: 'User logged in',
        userId: user.id,
        email: user.email,
      });

      res.json({
        success: true,
        message: 'Login successful',
        tokens: {
          accessToken,
          refreshToken,
        },
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
        },
      });
    } catch (error) {
      logger.error({
        message: 'Login error',
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
);

// ============================================
// POST /api/auth/refresh - تحديث الرمز
// ============================================
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required',
      });
    }

    // التحقق من الرمز
    const decoded = require('../utils/tokenManager.js').verifyToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
      });
    }

    // الحصول على بيانات المستخدم
    const result = await query(
      'SELECT id, email, role FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const user = result.rows[0];
    const newAccessToken = generateAccessToken(user.id, user.email, user.role);

    res.json({
      success: true,
      accessToken: newAccessToken,
    });
  } catch (error) {
    logger.error({
      message: 'Token refresh error',
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

// ============================================
// POST /api/auth/logout - تسجيل الخروج
// ============================================
router.post('/logout', authenticate, async (req, res) => {
  try {
    // تسجيل العملية
    await createAuditLog({
      userId: req.userId,
      action: 'USER_LOGOUT',
      resourceType: 'user',
      resourceId: req.userId,
      ipAddress: req.ip,
    });

    logger.info({
      message: 'User logged out',
      userId: req.userId,
    });

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    logger.error({
      message: 'Logout error',
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

// ============================================
// GET /api/auth/me - بيانات المستخدم الحالي
// ============================================
router.get('/me', authenticate, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, email, username, first_name, last_name, role, status, created_at, last_login_at
       FROM users WHERE id = $1`,
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const user = result.rows[0];

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        status: user.status,
        createdAt: user.created_at,
        lastLoginAt: user.last_login_at,
      },
    });
  } catch (error) {
    logger.error({
      message: 'Get current user error',
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

export default router;
