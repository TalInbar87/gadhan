// ================================================================
// auth-middleware.ts — בדיקת token + permissions
// ================================================================

import { verifyJwt, JwtPayload } from './jwt.ts';
import { createResponse }        from './response.ts';

const PERMISSION_MAP: Record<string, string> = {
  submit_data:    'write',
  get_existing:   'read',
  credit_data:    'credit',
  partial_credit: 'credit',
  transfer_items: 'transfer',
  swap_items:     'write',
  get_audit_log:  'audit_log',
  create_user:    'manage_users',
  // bunker — הכל read/write רגיל
};

export async function requireAuth(
  data: Record<string, unknown>,
  action: string,
  requiredPermission?: string
): Promise<{ payload: JwtPayload } | { error: Response }> {
  const token = data.token as string | undefined;
  if (!token) return { error: createResponse(401, 'Missing token', null) };

  const payload = await verifyJwt(token);
  if (!payload) return { error: createResponse(401, 'Invalid or expired token', null) };

  const perm = requiredPermission ?? PERMISSION_MAP[action];
  if (perm && payload.role !== 'admin' && !payload.permissions.includes(perm)) {
    return { error: createResponse(403, 'אין הרשאה לפעולה זו', null) };
  }

  return { payload };
}
