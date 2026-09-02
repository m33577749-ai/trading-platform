import { query } from '../config/database.js';
import { logger } from '../utils/logger.js';

export const createAuditLog = async ({
  userId,
  action,
  resourceType,
  resourceId,
  changes = null,
  ipAddress,
  metadata = null,
}) => {
  try {
    await query(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, changes, ip_address, metadata, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [
        userId,
        action,
        resourceType,
        resourceId,
        changes ? JSON.stringify(changes) : null,
        ipAddress,
        metadata ? JSON.stringify(metadata) : null,
      ]
    );
  } catch (error) {
    logger.error({
      message: 'Error creating audit log',
      error: error.message,
      action,
    });
  }
};
