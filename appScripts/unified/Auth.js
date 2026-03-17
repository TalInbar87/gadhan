/**
 * ================================================================
 * Authentication & Authorization - אבטחה והרשאות
 * ================================================================
 * JWTUtil           - יצירה ואימות JWT Tokens (HMAC-SHA256)
 * UserManager       - ניהול משתמשים וסיסמאות
 * AuditLogger       - רישום כל הפעולות
 * Authorization     - בדיקת הרשאות לפי תפקיד
 * EncryptedDataHandler - הצפנת XOR לתקשורת דפדפן↔שרת
 * ================================================================
 */

// ================================================================
// JWT Utilities
// ================================================================

class JWTUtil {

  static base64UrlEncode(str) {
    // שימוש ב-Blob כדי להבטיח קידוד UTF-8 נכון לתווים עבריים
    return Utilities.base64Encode(Utilities.newBlob(str, MimeType.TEXT_PLAIN).getBytes())
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  static base64UrlDecode(str) {
    let b = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    return Utilities.base64Decode(b);
  }

  static sign(payload, secret) {
    const h = this.base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const p = this.base64UrlEncode(JSON.stringify(payload));
    const sig = this.createSignature(h + '.' + p, secret);
    return h + '.' + p + '.' + sig;
  }

  static verify(token, secret) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const [h, p, sig] = parts;
      if (sig !== this.createSignature(h + '.' + p, secret)) return null;
      const payload = JSON.parse(
        Utilities.newBlob(this.base64UrlDecode(p)).getDataAsString()
      );
      if (payload.exp && payload.exp < Date.now() / 1000) return null;
      return payload;
    } catch (e) {
      Logger.log('❌ JWT verify error: ' + e);
      return null;
    }
  }

  static createSignature(data, secret) {
    return this.base64UrlEncode(Utilities.computeHmacSha256Signature(data, secret));
  }
}

// ================================================================
// User Manager
// ================================================================

class UserManager {

  static _getOrCreateSheet() {
    const ss = SpreadsheetApp.openById(CONFIG.SHEETS.USERS);
    return ss.getSheetByName('Users') || ss.insertSheet('Users');
  }

  static hashPassword(password) {
    const h = Utilities.base64Encode(
      Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password + CONFIG.JWT_SECRET)
    );
    return /^[=+\-@]/.test(h) ? ' ' + h : h; // מניעת formula injection (=, +, -, @)
  }

  static authenticate(username, password) {
    const sheet = this._getOrCreateSheet();
    const rows = sheet.getDataRange().getValues();
    const hash = this.hashPassword(password);
    for (let i = 1; i < rows.length; i++) {
      if (rows[i][0] === username && rows[i][1] === hash) {
        sheet.getRange(i + 1, 8).setValue(new Date().toISOString()); // Last Login
        return {
          username:       rows[i][0],
          role:           rows[i][2],
          personalNumber: rows[i][3],
          fullName:       rows[i][4],
          email:          rows[i][5]
        };
      }
    }
    return null;
  }

  static createUser(userData) {
    const sheet = this._getOrCreateSheet();
    const rows  = sheet.getDataRange().getValues();

    // בדוק כפילות לפי שם משתמש ומספר אישי
    for (let i = 1; i < rows.length; i++) {
      if (rows[i][0] === userData.username) {
        throw new Error('שם משתמש "' + userData.username + '" כבר קיים במערכת');
      }
      if (userData.personalNumber && rows[i][3] && rows[i][3] == userData.personalNumber) {
        throw new Error('מספר אישי ' + userData.personalNumber + ' כבר רשום במערכת (משתמש: ' + rows[i][0] + ')');
      }
    }

    sheet.appendRow([
      userData.username,
      this.hashPassword(userData.password),
      userData.role || 'user',
      userData.personalNumber || '',
      userData.fullName,
      userData.email || '',
      new Date().toISOString(),
      ''
    ]);
    return true;
  }

  static initializeUsersSheet() {
    const sheet = this._getOrCreateSheet();
    if (sheet.getLastRow() === 0) {
      sheet.appendRow(['Username', 'Password Hash', 'Role', 'Personal Number',
                       'Full Name', 'Email', 'Created At', 'Last Login']);
      sheet.appendRow(['admin', this.hashPassword('admin123'), 'admin', '',
                       'System Admin', '', new Date().toISOString(), '']);
      Logger.log('✅ Users sheet initialized with default admin');
    } else if (sheet.getLastRow() === 1) {
      sheet.appendRow(['admin', this.hashPassword('admin123'), 'admin', '',
                       'System Admin', '', new Date().toISOString(), '']);
      Logger.log('✅ Admin user added to existing sheet');
    }
  }
}

// ================================================================
// Audit Logger
// ================================================================

class AuditLogger {

  static _getOrCreateSheet() {
    const ss = SpreadsheetApp.openById(CONFIG.SHEETS.AUDIT_LOG);
    let sheet = ss.getSheetByName('Audit Log');
    if (!sheet) {
      sheet = ss.insertSheet('Audit Log');
      sheet.appendRow(['Timestamp', 'Username', 'Action', 'Resource',
                       'Personal Number', 'Details', 'IP Address', 'User Agent']);
      const hr = sheet.getRange(1, 1, 1, 8);
      hr.setBackground('#1a1a1a');
      hr.setFontColor('#FFFFFF');
      hr.setFontWeight('bold');
    }
    return sheet;
  }

  static log(username, action, resource, personalNumber, details, request) {
    try {
      this._getOrCreateSheet().appendRow([
        new Date().toISOString(),
        username || 'anonymous',
        action,
        resource,
        personalNumber || '',
        JSON.stringify(details || {}),
        (request && request.parameter && request.parameter['X-Forwarded-For']) || 'unknown',
        (request && request.parameter && request.parameter['User-Agent'])      || 'unknown'
      ]);
      Logger.log('📝 Audit: ' + username + ' - ' + action + ' - ' + resource);
    } catch (e) {
      Logger.log('❌ Audit error: ' + e);
    }
  }
}

// ================================================================
// Authorization
// ================================================================

class Authorization {

  static getPermissions(role) {
    for (const v of Object.values(CONFIG.ROLES)) {
      if (v.name === role) return v.permissions;
    }
    return [];
  }

  static canAccessResource(payload, resource, action) {
    if (payload.role === 'admin') return true;
    const map = {
      submit:       'write',
      read:         'read',
      delete:       'delete',
      view_reports: 'view_reports',
      manage_users: 'manage_users',
      credit:       'credit',
      audit_log:    'audit_log',
      transfer:     'transfer'
    };
    return this.getPermissions(payload.role).includes(map[action]);
  }
}

// ================================================================
// Bulk User Import
// ================================================================

/**
 * ייבוא משתמשים מרוכז מגיליון "Import" / "ייבוא" בתוך גיליון המשתמשים.
 *
 * מבנה הגיליון (שורה 1 = כותרות, מ-2 והלאה — נתונים):
 *   A=Username | B=Password | C=Role (user/admin/operator) | D=Personal Number | E=Full Name | F=Email (אופציונלי)
 *
 * שימוש: פתח Apps Script IDE → Run → bulkImportUsers
 */
function bulkImportUsers() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.USERS);
  const importSheet = ss.getSheetByName('Import') || ss.getSheetByName('ייבוא');

  if (!importSheet) {
    Logger.log('❌ לא נמצא גיליון "Import" או "ייבוא".');
    Logger.log('   צור גיליון בשם Import עם עמודות: Username | Password | Role | Personal Number | Full Name | Email');
    return;
  }

  const rows = importSheet.getDataRange().getValues();
  let success = 0, failed = 0, skipped = 0;

  for (let i = 1; i < rows.length; i++) {
    const username       = (rows[i][0] || '').toString().trim();
    const password       = (rows[i][1] || '').toString().trim();
    const role           = (rows[i][2] || 'user').toString().trim();
    const personalNumber = (rows[i][3] || '').toString().trim();
    const fullName       = (rows[i][4] || '').toString().trim();
    const email          = (rows[i][5] || '').toString().trim();

    if (!username || !password || !fullName) {
      Logger.log('⏭ שורה ' + (i + 1) + ' — דילוג (חסר username/password/fullName)');
      skipped++;
      continue;
    }

    try {
      UserManager.createUser({ username, password, role, personalNumber, fullName, email });
      Logger.log('✅ נוצר: ' + username + ' (' + fullName + ')');
      success++;
    } catch (e) {
      Logger.log('⚠️ שורה ' + (i + 1) + ' (' + username + '): ' + e.message);
      failed++;
    }
  }

  Logger.log('────────────────────────────────────────');
  Logger.log('📊 סיום ייבוא: ' + success + ' נוצרו | ' + failed + ' נכשלו | ' + skipped + ' דולגו');
}

// ================================================================
// Encrypted Data Handler  (דפדפן ↔ שרת)
// XOR + URL-encode + Base64
// ================================================================

class EncryptedDataHandler {

  static encrypt(data, key) {
    const s = JSON.stringify(data);
    let enc = '';
    for (let i = 0; i < s.length; i++) {
      enc += String.fromCharCode(s.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return Utilities.base64Encode(encodeURIComponent(enc));
  }

  static decrypt(encryptedData, key) {
    const decoded = decodeURIComponent(
      Utilities.newBlob(Utilities.base64Decode(encryptedData)).getDataAsString()
    );
    let dec = '';
    for (let i = 0; i < decoded.length; i++) {
      dec += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return JSON.parse(dec);
  }
}
