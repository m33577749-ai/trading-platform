import express from 'express';
import { body, validationResult } from 'express-validator';
import { query } from '../config/database.js';
import { authenticate } from '../middleware/auth.js';
import bcrypt from 'bcryptjs';
import { logger } from '../utils/logger.js';
import { createAuditLog } from '../services/auditLogService.js';

const router = express.Router();

// ============================================
// GET /api/users/:id - الحصول على بيانات المستخدم
// ============================================
router.get('/:id', authenticate, async (req, res) => {
  try {
    const userId = req.params.id;

    // التحقق من الصلاحيات (يمكن للمستخدم رؤية بيانات نفسه فقط)
    if (req.userId !== parseInt(userId) && req.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to access this resource',
      });
    }

    const result = await query(
      `SELECT id, email, username, first_name, last_name, role, status, created_at, updated_at
       FROM users WHERE id = $1`,
      [userId]
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
        updatedAt: user.updated_at,
      },
    });
  } catch (error) {
    logger.error({
      message: 'Get user error',
      error: error.message,
      userId: req.userId,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

// ============================================
// PUT /api/users/:id - تحديث بيانات المستخدم
// ============================================
router.put(
  '/:id',
  authenticate,
  [
    body('firstName').optional().isLength({ min: 2 }),
    body('lastName').optional().isLength({ min: 2 }),
    body('password').optional().isLength({ min: 8 }),
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

      const userId = req.params.id;
      const { firstName, lastName, password } = req.body;

      // التحقق من الصلاحيات
      if (req.userId !== parseInt(userId) && req.role !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'You do not have permission to update this user',
        });
      }

      // التحقق من وجود المستخدم
      const userExists = await query('SELECT id FROM users WHERE id = $1', [userId]);
      if (userExists.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      let updateFields = [];
      let updateValues = [];
      let paramCount = 1;

      if (firstName) {
        updateFields.push(`first_name = $${paramCount}`);
        updateValues.push(firstName);
        paramCount++;
      }

      if (lastName) {
        updateFields.push(`last_name = $${paramCount}`);
        updateValues.push(lastName);
        paramCount++;
      }

      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updateFields.push(`password_hash = $${paramCount}`);
        updateValues.push(hashedPassword);
        paramCount++;
      }

      if (updateFields.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'No fields to update',
        });
      }

      updateFields.push(`updated_at = NOW()`);
      updateValues.push(userId);

      const updateQuery = `
        UPDATE users
        SET ${updateFields.join(', ')}
        WHERE id = $${paramCount}
        RETURNING id, email, username, first_name, last_name, role, status, updated_at
      `;

      const result = await query(updateQuery, updateValues);
      const updatedUser = result.rows[0];

      // تسجيل العملية
      await createAuditLog({
        userId: req.userId,
        action: 'USER_UPDATED',
        resourceType: 'user',
        resourceId: userId,
        changes: {
          firstName,
          lastName,
          passwordChanged: !!password,
        },
        ipAddress: req.ip,
      });

      logger.info({
        message: 'User updated',
        userId,
        updatedBy: req.userId,
      });

      res.json({
        success: true,
        message: 'User updated successfully',
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          username: updatedUser.username,
          firstName: updatedUser.first_name,
          lastName: updatedUser.last_name,
          role: updatedUser.role,
          status: updatedUser.status,
          updatedAt: updatedUser.updated_at,
        },
      });
    } catch (error) {
      logger.error({
        message: 'Update user error',
        error: error.message,
        userId: req.userId,
      });
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
);

export default router;
