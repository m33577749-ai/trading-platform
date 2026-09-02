import express from 'express';
import { query } from '../config/database.js';
import { authenticate, authorize } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';

const router = express.Router();

// ============================================
// GET /api/audit-logs - سجلات التدقيق (Admin Only)
// ============================================
router.get('/', authenticate, authorize('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 50;
    const userId = req.query.userId;
    const action = req.query.action;
    const startDate = req.query.startDate;
    const endDate = req.query.endDate;
    const offset = (page - 1) * pageSize;

    let whereClause = 'WHERE 1=1';
    let params = [];
    let paramCount = 1;

    if (userId) {
      whereClause += ` AND user_id = $${paramCount}`;
      params.push(userId);
      paramCount++;
    }

    if (action) {
      whereClause += ` AND action ILIKE $${paramCount}`;
      params.push(`%${action}%`);
      paramCount++;
    }

    if (startDate) {
      whereClause += ` AND timestamp >= $${paramCount}`;
      params.push(startDate);
      paramCount++;
    }

    if (endDate) {
      whereClause += ` AND timestamp <= $${paramCount}`;
      params.push(endDate);
      paramCount++;
    }

    // الحصول على عدد السجلات الكلي
    const countResult = await query(
      `SELECT COUNT(*) FROM audit_logs ${whereClause}`,
      params
    );
    const total = parseInt(countResult.rows[0].count);

    // الحصول على السجلات
    const result = await query(
      `SELECT id, user_id, action, resource_type, resource_id, changes, ip_address, timestamp, metadata
       FROM audit_logs ${whereClause}
       ORDER BY timestamp DESC
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
      logs: result.rows.map(log => ({
        id: log.id,
        userId: log.user_id,
        action: log.action,
        resourceType: log.resource_type,
        resourceId: log.resource_id,
        changes: log.changes,
        ipAddress: log.ip_address,
        timestamp: log.timestamp,
        metadata: log.metadata,
      })),
    });
  } catch (error) {
    logger.error({
      message: 'Get audit logs error',
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
// GET /api/audit-logs/:id - التفاصيل الكاملة لسجل معين
// ============================================
router.get('/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const logId = req.params.id;

    const result = await query(
      `SELECT id, user_id, action, resource_type, resource_id, changes, ip_address, timestamp, metadata
       FROM audit_logs WHERE id = $1`,
      [logId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Audit log not found',
      });
    }

    const log = result.rows[0];

    res.json({
      success: true,
      log: {
        id: log.id,
        userId: log.user_id,
        action: log.action,
        resourceType: log.resource_type,
        resourceId: log.resource_id,
        changes: log.changes,
        ipAddress: log.ip_address,
        timestamp: log.timestamp,
        metadata: log.metadata,
      },
    });
  } catch (error) {
    logger.error({
      message: 'Get audit log error',
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
