import express from 'express';
import { query } from '../config/database.js';
import { authenticate } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import { createAuditLog } from '../services/auditLogService.js';

const router = express.Router();

// ============================================
// GET /api/wallets - قائمة محافظ المستخدم
// ============================================
router.get('/', authenticate, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, user_id, currency, balance, created_at, updated_at
       FROM wallets WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.userId]
    );

    res.json({
      success: true,
      wallets: result.rows.map(w => ({
        id: w.id,
        userId: w.user_id,
        currency: w.currency,
        balance: w.balance,
        createdAt: w.created_at,
        updatedAt: w.updated_at,
      })),
    });
  } catch (error) {
    logger.error({
      message: 'Get wallets error',
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
// GET /api/wallets/:id - الحصول على محفظة محددة
// ============================================
router.get('/:id', authenticate, async (req, res) => {
  try {
    const walletId = req.params.id;

    const result = await query(
      `SELECT id, user_id, currency, balance, created_at, updated_at
       FROM wallets WHERE id = $1`,
      [walletId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found',
      });
    }

    const wallet = result.rows[0];

    // التحقق من الصلاحيات
    if (wallet.user_id !== req.userId && req.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to access this wallet',
      });
    }

    res.json({
      success: true,
      wallet: {
        id: wallet.id,
        userId: wallet.user_id,
        currency: wallet.currency,
        balance: wallet.balance,
        createdAt: wallet.created_at,
        updatedAt: wallet.updated_at,
      },
    });
  } catch (error) {
    logger.error({
      message: 'Get wallet error',
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
// GET /api/wallets/:id/transactions - تاريخ العمليات
// ============================================
router.get('/:id/transactions', authenticate, async (req, res) => {
  try {
    const walletId = req.params.id;
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    const offset = (page - 1) * pageSize;

    // التحقق من الصلاحيات
    const walletResult = await query(
      'SELECT user_id FROM wallets WHERE id = $1',
      [walletId]
    );

    if (walletResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found',
      });
    }

    if (walletResult.rows[0].user_id !== req.userId && req.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to access these transactions',
      });
    }

    // الحصول على عدد العمليات الكلي
    const countResult = await query(
      'SELECT COUNT(*) FROM transactions WHERE wallet_id = $1',
      [walletId]
    );
    const total = parseInt(countResult.rows[0].count);

    // الحصول على العمليات
    const result = await query(
      `SELECT id, wallet_id, type, amount, status, metadata, created_at
       FROM transactions WHERE wallet_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [walletId, pageSize, offset]
    );

    res.json({
      success: true,
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
      },
      transactions: result.rows.map(t => ({
        id: t.id,
        walletId: t.wallet_id,
        type: t.type,
        amount: t.amount,
        status: t.status,
        metadata: t.metadata,
        createdAt: t.created_at,
      })),
    });
  } catch (error) {
    logger.error({
      message: 'Get transactions error',
      error: error.message,
      userId: req.userId,
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

export default router;
