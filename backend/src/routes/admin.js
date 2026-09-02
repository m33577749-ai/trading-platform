import express from 'express';
import { query } from '../config/database.js';
import { authenticate, authorize } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import { createAuditLog } from '../services/auditLogService.js';

const router = express.Router();

// ============================================
// GET /api/admin/users - قائمة جميع المستخدمين (Admin Only)
// ============================================
router.get('/users', authenticate, authorize('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    const status = req.query.status;
    const role = req.query.role;
    const offset = (page - 1) * pageSize;

    let whereClause = 'WHERE 1=1';
    let params = [];
    let paramCount = 1;

    if (status) {
      whereClause += ` AND status = $${paramCount}`;
      params.push(status);
      paramCount++;
    }

    if (role) {
      whereClause += ` AND role = $${paramCount}`;
      params.push(role);
      paramCount++;
    }

    // الحصول على عدد المستخدمين الكلي
    const countResult = await query(
      `SELECT COUNT(*) FROM users ${whereClause}`,
      params
    );
    const total = parseInt(countResult.rows[0].count);

    // الحصول على المستخدمين
    const result = await query(
      `SELECT id, email, username, first_name, last_name, role, status, created_at, last_login_at
       FROM users ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramCount} OFFSET $${paramCount + 1}`,
      [...params, pageSize, offset]
    );

    res.json({
      success: true,
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
      },
      users: result.rows.map(u => ({
        id: u.id,
        email: u.email,
        username: u.username,
        firstName: u.first_name,
        lastName: u.last_name,
        role: u.role,
        status: u.status,
        createdAt: u.created_at,
        lastLoginAt: u.last_login_at,
      })),
    });
  } catch (error) {
    logger.error({
      message: 'Get users error',
      error: error.message,
      adminId: req.userId,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

// ============================================
// PUT /api/admin/users/:id/role - تغيير دور المستخدم
// ============================================
router.put('/users/:id/role', authenticate, authorize('admin'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { role } = req.body;

    const validRoles = ['user', 'admin', 'moderator'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role',
      });
    }

    // التحقق من وجود المستخدم
    const userExists = await query('SELECT role FROM users WHERE id = $1', [userId]);
    if (userExists.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const oldRole = userExists.rows[0].role;

    // تحديث الدور
    const result = await query(
      `UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2
       RETURNING id, email, username, role`,
      [role, userId]
    );

    const updatedUser = result.rows[0];

    // تسجيل العملية
    await createAuditLog({
      userId: req.userId,
      action: 'USER_ROLE_CHANGED',
      resourceType: 'user',
      resourceId: userId,
      changes: {
        oldRole,
        newRole: role,
      },
      ipAddress: req.ip,
    });

    logger.info({
      message: 'User role changed',
      userId,
      oldRole,
      newRole: role,
      changedBy: req.userId,
    });

    res.json({
      success: true,
      message: 'User role updated successfully',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        username: updatedUser.username,
        role: updatedUser.role,
      },
    });
  } catch (error) {
    logger.error({
      message: 'Update user role error',
      error: error.message,
      adminId: req.userId,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

// ============================================
// PUT /api/admin/users/:id/status - تغيير حالة المستخدم
// ============================================
router.put('/users/:id/status', authenticate, authorize('admin'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { status } = req.body;

    const validStatuses = ['active', 'suspended', 'deleted'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status',
      });
    }

    // التحقق من وجود المستخدم
    const userExists = await query('SELECT status FROM users WHERE id = $1', [userId]);
    if (userExists.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const oldStatus = userExists.rows[0].status;

    // تحديث الحالة
    const result = await query(
      `UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2
       RETURNING id, email, username, status`,
      [status, userId]
    );

    const updatedUser = result.rows[0];

    // تسجيل العملية
    await createAuditLog({
      userId: req.userId,
      action: 'USER_STATUS_CHANGED',
      resourceType: 'user',
      resourceId: userId,
      changes: {
        oldStatus,
        newStatus: status,
      },
      ipAddress: req.ip,
    });

    logger.info({
      message: 'User status changed',
      userId,
      oldStatus,
      newStatus: status,
      changedBy: req.userId,
    });

    res.json({
      success: true,
      message: 'User status updated successfully',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        username: updatedUser.username,
        status: updatedUser.status,
      },
    });
  } catch (error) {
    logger.error({
      message: 'Update user status error',
      error: error.message,
      adminId: req.userId,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

export default router;
