/**
 * ================================================================
 * מערכת ניהול מאוחדת - גדחה"ו קומנדו 8219
 * Unified Google Apps Script - Configuration
 * ================================================================
 * קונפיגורציה אחת לכל המערכת:
 * אימות, הרשאות, Google Sheet IDs, והגדרות מודולים
 * ================================================================
 */

const CONFIG = {

  // ===== Authentication =====
  JWT_SECRET: 'BagadHatzamKomando8219SecretKey2026XyZ_STATIC_2026',
  TOKEN_EXPIRATION: 3600, // שעה (שניות)

  // ===== General =====
  TIMEZONE: 'Asia/Jerusalem',

  // ===== Google Sheet IDs =====
  SHEETS: {
    USERS:     '1x3QU2_6DJmOsBybj6zxAPKhJGFs84NGxruNMjDstz7E',   // גיליון משתמשים
    AUDIT_LOG: '16dqeWkWk3KQYJzQYB7AhUhgJsHhR_7wXjAGVScaQ7Ks',  // יומן ביקורת
    WEAPONS:   '1kPB-CL0dY7J-J_-KmOYvLUNc9Zw4vJhDYij_SOwRJN0',  // גיליון נשקים
    RADIO:     '1jUDDvC2PPYOcEWHgb2fc5Jds_K_YYhjveHYIgAurEBc'   // גיליון קשר
  },

  // ===== Weapons Module Settings =====
  // מבנה עמודות גיליון נשקים:
  // A=תאריך | B=שם מלא | C=מספר אישי | D=טלפון | E=מייל | F=מסגרת
  // G=סוג נשק | H=מספר נשק | I=טריג׳ | J=ליאור | K=פגיון | L=זאבון
  // M=m5 | N=שח"ע | O=עכבר | P=עדי | Q=עידו | R=קירו
  // S=משקפה | T=מצפן | U=ציין | V=פק
  WEAPONS: {
    MAIN_SHEET_NAME: 'כל הרשומות',
    HEADER_COLOR:    '#2F5233',   // ירוק צבאי
    DEFAULT_UNIT:    'ללא מסגרת',
    PN_COLUMN:       3            // עמודה C (1-indexed) = מספר אישי
  },

  // ===== Radio Module Settings =====
  // מבנה עמודות גיליון קשר:
  // A=מספר אישי | B=תאריך | C=שם מלא | D=טלפון | E=מייל | F=מסגרת
  // G=624 | H=91 | I=עמוד | J=מספר עמוד | K=מגבר | L=מתאם קשיח
  // M=אנטנה לונג | N=מעד | O=מתאם גמיש | P=אנטנה שורט | Q=רמק
  // R=מדונה | S=תפוח | T=אגס
  RADIO: {
    MAIN_SHEET_NAME: 'כל הרשומות',
    HEADER_COLOR:    '#1e40af',   // כחול
    DEFAULT_UNIT:    'ללא מסגרת',
    PN_COLUMN:       1            // עמודה A (1-indexed) = מספר אישי
  },

  // ===== Roles & Permissions =====
  ROLES: {
    ADMIN:    { name: 'admin',    permissions: ['read', 'write', 'delete', 'view_reports', 'manage_users'] },
    OPERATOR: { name: 'operator', permissions: ['read', 'write', 'view_reports'] },
    VIEWER:   { name: 'viewer',   permissions: ['read', 'view_reports'] },
    USER:     { name: 'user',     permissions: ['write'] }
  }

};
