/**
 * ================================================================
 * Google Apps Script - מערכת אבטחה והרשאות (Middleware)
 * ================================================================
 * 
 * תיאור: סקריפט Standalone לניהול Authentication ו-Authorization
 * 
 * Sheets שבשימוש:
 * - Users Sheet (ID: 1x3QU2_6DJmOsBybj6zxAPKhJGFs84NGxruNMjDstz7E)
 * - Audit Log Sheet (ID: 16dqeWkWk3KQYJzQYB7AhUhgJsHhR_7wXjAGVScaQ7Ks)
 * 
 * תפקידים:
 * 1. התחברות משתמשים (Login/Authentication)
 * 2. בדיקת הרשאות (Authorization)
 * 3. יצירת וניהול JWT Tokens
 * 4. הצפנת נתונים
 * 5. רישום פעולות ב-Audit Log
 * 6. העברת נתונים מוצפנים לסקריפטים של נשקים/קשר
 * 
 * הוראות התקנה:
 * 1. צור Apps Script חדש (Standalone - לא קשור לשום Sheet)
 * 2. הדבק את הקוד הזה
 * 3. עדכן את CONFIG.SHEETS עם ה-IDs של הגיליונות שלך
 * 4. עדכן את CONFIG.ORIGINAL_SCRIPTS עם ה-URLs של הסקריפטים של נשקים וקשר
 * 5. Deploy > New deployment > Web app
 * 6. Execute as: Me | Who has access: Anyone
 * 7. העתק את ה-URL והדבק ב-HTML (API_URL)
 * 
 * Flow:
 * Frontend → permissionsAppScript (זה!) → weaponAppScript/radioAppScript → Google Sheets
 * 
 * ================================================================
 */

// ================================================================
// קונפיגורציה - ערוך את הערכים האלה!
// ================================================================

const CONFIG = {
  // JWT Secret - שנה למחרוזת רנדומלית!
  JWT_SECRET: 'BagadHatzamKomando8219SecretKey2026XyZ_STATIC_2026',
  
  // תוקף Token (בשניות)
  TOKEN_EXPIRATION: 3600, // שעה אחת
  
  // Google Sheet IDs
  SHEETS: {
    USERS: '1x3QU2_6DJmOsBybj6zxAPKhJGFs84NGxruNMjDstz7E',        // גיליון משתמשים
    AUDIT_LOG: '16dqeWkWk3KQYJzQYB7AhUhgJsHhR_7wXjAGVScaQ7Ks',   // יומן ביקורת
    WEAPONS: '1kPB-CL0dY7J-J_-KmOYvLUNc9Zw4vJhDYij_SOwRJN0',     // גיליון נשקים (לעתיד)
    RADIO: '1jUDDvC2PPYOcEWHgb2fc5Jds_K_YYhjveHYIgAurEBc'        // גיליון קשר (לעתיד)
  },
  
  // URLs של הסקריפטים המקוריים (להעברת נתונים אחרי Authentication)
  ORIGINAL_SCRIPTS: {
    WEAPONS: 'https://script.google.com/macros/s/AKfycby_vOgDCI8ZHR3sH42fMkXpDuCljYrpgZ3SO7YgnC97Yg0Rsm3y0P_uj0VNpnYo12Xg/exec',
    RADIO: 'https://script.google.com/macros/s/AKfycbxG1ymau8BHFFzIyqPqqe-jSIEZgc00SHoV4LMANhQbBRDm45U0RK1Ajh6m0Xcn099X/exec'
  },
  
  // תפקידים והרשאות
  ROLES: {
    ADMIN: {
      name: 'admin',
      permissions: ['read', 'write', 'delete', 'view_reports', 'manage_users']
    },
    OPERATOR: {
      name: 'operator',
      permissions: ['read', 'write', 'view_reports']
    },
    VIEWER: {
      name: 'viewer',
      permissions: ['read', 'view_reports']
    },
    USER: {
      name: 'user',
      permissions: ['write'] // יכול רק לשלוח את הנתונים שלו
    }
  }
};

// ================================================================
// JWT Utilities - ניהול Tokens
// ================================================================

/**
 * מחלקה לניהול JWT Tokens
 * משתמשת ב-HMAC-SHA256
 */
class JWTUtil {
  /**
   * Encode Base64 URL Safe
   */
  static base64UrlEncode(str) {
    const base64 = Utilities.base64Encode(str);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
  
  /**
   * Decode Base64 URL Safe
   */
  static base64UrlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return Utilities.base64Decode(base64);
  }
  
  /**
   * יצירת JWT Token
   */
  static sign(payload, secret) {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };
    
    const headerEncoded = this.base64UrlEncode(JSON.stringify(header));
    const payloadEncoded = this.base64UrlEncode(JSON.stringify(payload));
    const signature = this.createSignature(headerEncoded + '.' + payloadEncoded, secret);
    
    return headerEncoded + '.' + payloadEncoded + '.' + signature;
  }
  
  /**
   * אימות JWT Token
   */
  static verify(token, secret) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }
      
      const [headerEncoded, payloadEncoded, signature] = parts;
      const expectedSignature = this.createSignature(headerEncoded + '.' + payloadEncoded, secret);
      
      // בדיקת חתימה
      if (signature !== expectedSignature) {
        return null;
      }
      
      // פענוח Payload
      const payload = JSON.parse(
        Utilities.newBlob(this.base64UrlDecode(payloadEncoded)).getDataAsString()
      );
      
      // בדיקת תוקף
      if (payload.exp && payload.exp < Date.now() / 1000) {
        return null; // Token פג תוקף
      }
      
      return payload;
      
    } catch (e) {
      Logger.log('❌ JWT verification error: ' + e.toString());
      return null;
    }
  }
  
  /**
   * יצירת חתימה
   */
  static createSignature(data, secret) {
    const signature = Utilities.computeHmacSha256Signature(data, secret);
    return this.base64UrlEncode(signature);
  }
}

// ================================================================
// User Management - ניהול משתמשים
// ================================================================

/**
 * מחלקה לניהול משתמשים
 */
class UserManager {
  /**
   * קבלת גיליון המשתמשים
   */
  static getUsersSheet() {
    const ss = SpreadsheetApp.openById(CONFIG.SHEETS.USERS);
    return ss.getSheetByName('Users') || ss.insertSheet('Users');
  }
  
  /**
   * אתחול גיליון משתמשים עם משתמש admin ברירת מחדל
   */
  static initializeUsersSheet() {
    const sheet = this.getUsersSheet();
    const lastRow = sheet.getLastRow();
    
    // אם הגיליון ריק לגמרי
    if (lastRow === 0) {
      // הוסף כותרות
      sheet.appendRow([
        'Username', 'Password Hash', 'Role', 
        'Personal Number', 'Full Name', 'Email', 
        'Created At', 'Last Login'
      ]);
      
      // הוסף משתמש admin ברירת מחדל (סיסמה: admin123)
      const adminHash = this.hashPassword('admin123');
      sheet.appendRow([
        'admin', adminHash, 'admin', '', 
        'System Admin', '', new Date().toISOString(), ''
      ]);
      
      Logger.log('✅ Users sheet initialized with admin user');
      
    } else if (lastRow === 1) {
      // יש כותרות אבל אין משתמשים - הוסף admin
      const adminHash = this.hashPassword('admin123');
      sheet.appendRow([
        'admin', adminHash, 'admin', '', 
        'System Admin', '', new Date().toISOString(), ''
      ]);
      
      Logger.log('✅ Admin user added to existing sheet');
    }
  }
  
  /**
   * Hash לסיסמה (SHA-256)
   */
  static hashPassword(password) {
    const hash = Utilities.base64Encode(
      Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256, 
        password + CONFIG.JWT_SECRET
      )
    );
    // מניעת formula injection
    return hash.charAt(0) === '=' ? ' ' + hash : hash;
  }
  
  /**
   * אימות משתמש
   */
  static authenticate(username, password) {
    const sheet = this.getUsersSheet();
    const data = sheet.getDataRange().getValues();
    const passwordHash = this.hashPassword(password);
    
    // חיפוש המשתמש
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === username && data[i][1] === passwordHash) {
        // עדכן Last Login
        sheet.getRange(i + 1, 8).setValue(new Date().toISOString());
        
        // החזר פרטי משתמש
        return {
          username: data[i][0],
          role: data[i][2],
          personalNumber: data[i][3],
          fullName: data[i][4],
          email: data[i][5]
        };
      }
    }
    
    return null; // משתמש לא נמצא או סיסמה שגויה
  }
  
  /**
   * יצירת משתמש חדש
   */
  static createUser(userData) {
    const sheet = this.getUsersSheet();
    const passwordHash = this.hashPassword(userData.password);
    
    sheet.appendRow([
      userData.username,
      passwordHash,
      userData.role || 'user',
      userData.personalNumber || '',
      userData.fullName,
      userData.email,
      new Date().toISOString(),
      ''
    ]);
    
    return true;
  }
  
  /**
   * קבלת משתמש לפי שם משתמש
   */
  static getUserByUsername(username) {
    const sheet = this.getUsersSheet();
    const data = sheet.getDataRange().getValues();
    
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === username) {
        return {
          username: data[i][0],
          role: data[i][2],
          personalNumber: data[i][3],
          fullName: data[i][4],
          email: data[i][5]
        };
      }
    }
    
    return null;
  }
}

// ================================================================
// Audit Logger - רישום פעולות
// ================================================================

/**
 * מחלקה לרישום כל הפעולות במערכת
 */
class AuditLogger {
  /**
   * קבלת גיליון Audit Log
   */
  static getAuditSheet() {
    const ss = SpreadsheetApp.openById(CONFIG.SHEETS.AUDIT_LOG);
    return ss.getSheetByName('Audit Log') || ss.insertSheet('Audit Log');
  }
  
  /**
   * אתחול גיליון Audit Log
   */
  static initializeAuditSheet() {
    const sheet = this.getAuditSheet();
    if (sheet.getLastRow() === 0) {
      sheet.appendRow([
        'Timestamp', 'Username', 'Action', 'Resource', 
        'Personal Number', 'Details', 'IP Address', 'User Agent'
      ]);
      
      // עיצוב כותרות
      const headerRange = sheet.getRange(1, 1, 1, 8);
      headerRange.setBackground("#1a1a1a");
      headerRange.setFontColor("#FFFFFF");
      headerRange.setFontWeight("bold");
    }
  }
  
  /**
   * רישום פעולה
   */
  static log(username, action, resource, personalNumber, details, request) {
    try {
      const sheet = this.getAuditSheet();
      
      // קבל IP ו-User Agent מה-request
      const ipAddress = this.getIpAddress(request);
      const userAgent = this.getUserAgent(request);
      
      sheet.appendRow([
        new Date().toISOString(),
        username || 'anonymous',
        action,
        resource,
        personalNumber || '',
        JSON.stringify(details || {}),
        ipAddress,
        userAgent
      ]);
      
      Logger.log(`📝 Audit: ${username} - ${action} - ${resource}`);
      
    } catch (e) {
      Logger.log('❌ Audit log error: ' + e.toString());
    }
  }
  
  /**
   * קבלת IP Address
   */
  static getIpAddress(request) {
    try {
      if (request && request.parameter && request.parameter['X-Forwarded-For']) {
        return request.parameter['X-Forwarded-For'];
      }
      return 'unknown';
    } catch (e) {
      return 'unknown';
    }
  }
  
  /**
   * קבלת User Agent
   */
  static getUserAgent(request) {
    try {
      if (request && request.parameter && request.parameter['User-Agent']) {
        return request.parameter['User-Agent'];
      }
      return 'unknown';
    } catch (e) {
      return 'unknown';
    }
  }
}

// ================================================================
// Authorization - בדיקת הרשאות
// ================================================================

/**
 * מחלקה לבדיקת הרשאות
 */
class Authorization {
  /**
   * קבלת הרשאות לפי תפקיד
   */
  static getPermissions(role) {
    for (const [key, value] of Object.entries(CONFIG.ROLES)) {
      if (value.name === role) {
        return value.permissions;
      }
    }
    return [];
  }
  
  /**
   * בדיקה אם למשתמש יש הרשאה ספציפית
   */
  static hasPermission(payload, permission) {
    const permissions = this.getPermissions(payload.role);
    return permissions.includes(permission);
  }
  
  /**
   * בדיקה אם למשתמש יש גישה למשאב
   */
  static canAccessResource(payload, resource, action) {
    const permissions = this.getPermissions(payload.role);
    
    // Admin יכול הכל
    if (payload.role === 'admin') {
      return true;
    }
    
    // מיפוי פעולות להרשאות
    const actionPermissionMap = {
      'submit': 'write',
      'read': 'read',
      'delete': 'delete',
      'view_reports': 'view_reports',
      'manage_users': 'manage_users'
    };
    
    const requiredPermission = actionPermissionMap[action];
    return permissions.includes(requiredPermission);
  }
}

// ================================================================
// Encrypted Data Handler - הצפנת נתונים
// ================================================================

/**
 * מחלקה להצפנה ופענוח נתונים
 * משתמשת ב-XOR Encryption פשוטה
 */
class EncryptedDataHandler {
  /**
   * הצפנת נתונים
   */
  static encrypt(data, key) {
    const jsonStr = JSON.stringify(data);
    let encrypted = '';
    
    // XOR encryption
    for (let i = 0; i < jsonStr.length; i++) {
      encrypted += String.fromCharCode(
        jsonStr.charCodeAt(i) ^ key.charCodeAt(i % key.length)
      );
    }
    
    // URL encoding לתמיכה ב-Unicode
    const urlEncoded = encodeURIComponent(encrypted);
    
    // Base64 encoding
    return Utilities.base64Encode(urlEncoded);
  }
  
  /**
   * פענוח נתונים
   */
  static decrypt(encryptedData, key) {
    // Decode Base64
    const decoded = Utilities.newBlob(
      Utilities.base64Decode(encryptedData)
    ).getDataAsString();
    
    // Decode URI
    const urlDecoded = decodeURIComponent(decoded);
    
    // XOR decrypt
    let decrypted = '';
    for (let i = 0; i < urlDecoded.length; i++) {
      decrypted += String.fromCharCode(
        urlDecoded.charCodeAt(i) ^ key.charCodeAt(i % key.length)
      );
    }
    
    return JSON.parse(decrypted);
  }
}

// ================================================================
// Main Handlers - טיפול בבקשות
// ================================================================

/**
 * טיפול בבקשות POST
 */
function doPost(e) {
  try {
    Logger.log('🎯 doPost called');
    
    // פענוח הנתונים
    let data;
    if (e.postData && e.postData.contents) {
      // JSON ישיר מ-postData
      data = JSON.parse(e.postData.contents);
    } else if (e.parameter && e.parameter.data) {
      // URL-encoded JSON מ-parameter
      const decodedData = decodeURIComponent(e.parameter.data);
      data = JSON.parse(decodedData);
    } else {
      return createResponse(400, 'No data provided', null);
    }
    
    const action = data.action;
    Logger.log('Action: ' + action);
    
    // ניתוב לפי פעולה
    switch (action) {
      case 'login':
        return handleLogin(data, e);
      case 'verify_token':
        return handleVerifyToken(data, e);
      case 'submit_data':
        return handleSubmitData(data, e);
      case 'get_existing':
        return handleGetExisting(data, e);
      case 'create_user':
        return handleCreateUser(data, e);
      default:
        return createResponse(400, 'Unknown action: ' + action, null);
    }
    
  } catch (error) {
    Logger.log('❌ Error in doPost: ' + error.toString());
    Logger.log('Error details: ' + error.stack);
    return createResponse(500, 'Server error: ' + error.toString(), null);
  }
}

/**
 * טיפול בהתחברות
 */
function handleLogin(data, request) {
  const { username, password } = data;
  
  Logger.log('🔐 Login attempt: ' + username);
  
  // אימות משתמש
  const user = UserManager.authenticate(username, password);
  
  if (!user) {
    AuditLogger.log(username, 'LOGIN_FAILED', 'AUTH', null, 
                   { reason: 'Invalid credentials' }, request);
    return createResponse(401, 'Invalid username or password', null);
  }
  
  // יצירת JWT Token
  const payload = {
    username: user.username,
    role: user.role,
    personalNumber: user.personalNumber,
    fullName: user.fullName,
    email: user.email,
    permissions: Authorization.getPermissions(user.role),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + CONFIG.TOKEN_EXPIRATION
  };
  
  const token = JWTUtil.sign(payload, CONFIG.JWT_SECRET);
  
  // רישום בAudit Log
  AuditLogger.log(username, 'LOGIN_SUCCESS', 'AUTH', null, 
                 { role: user.role }, request);
  
  Logger.log('✅ Login successful for: ' + username);
  
  return createResponse(200, 'Login successful', {
    token: token,
    user: {
      username: user.username,
      role: user.role,
      fullName: user.fullName,
      email: user.email,
      permissions: Authorization.getPermissions(user.role)
    }
  });
}

/**
 * אימות Token
 */
function handleVerifyToken(data, request) {
  const { token } = data;
  
  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  
  if (!payload) {
    return createResponse(401, 'Invalid or expired token', null);
  }
  
  return createResponse(200, 'Token is valid', {
    user: {
      username: payload.username,
      role: payload.role,
      permissions: payload.permissions
    }
  });
}

/**
 * שליחת נתונים (מעבירה לסקריפט המקורי)
 */
function handleSubmitData(data, request) {
  const { token, formData, formType } = data;
  
  // אימות Token
  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) {
    return createResponse(401, 'Invalid or expired token', null);
  }
  
  // בדיקת הרשאות
  if (!Authorization.canAccessResource(payload, formType, 'submit')) {
    AuditLogger.log(payload.username, 'SUBMIT_DENIED', formType, 
                   formData.personalNumber, { reason: 'Insufficient permissions' }, request);
    return createResponse(403, 'Insufficient permissions', null);
  }
  
  // פענוח הנתונים
  let decryptedData;
  try {
    decryptedData = EncryptedDataHandler.decrypt(formData, CONFIG.JWT_SECRET);
    Logger.log('✅ Data decrypted successfully');
  } catch (e) {
    Logger.log('❌ Decryption error: ' + e.toString());
    return createResponse(400, 'Invalid encrypted data', null);
  }
  
  // הוספת metadata
  decryptedData.submittedBy = payload.username;
  decryptedData.submittedAt = new Date().toISOString();
  
  // העברה לסקריפט המקורי
  const originalScriptUrl = formType === 'weapons' 
    ? CONFIG.ORIGINAL_SCRIPTS.WEAPONS 
    : CONFIG.ORIGINAL_SCRIPTS.RADIO;
  
  if (!originalScriptUrl) {
    return createResponse(500, 'Original script URL not configured', null);
  }
  
  try {
    Logger.log('📤 Forwarding to: ' + originalScriptUrl);
    
    const response = UrlFetchApp.fetch(originalScriptUrl, {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(decryptedData),
      muteHttpExceptions: true
    });
    
    const responseCode = response.getResponseCode();
    
    if (responseCode >= 200 && responseCode < 300) {
      // הצלחה
      AuditLogger.log(
        payload.username, 
        'DATA_SUBMITTED', 
        formType, 
        decryptedData.personalNumber,
        { action: 'submit', forwardedTo: originalScriptUrl },
        request
      );
      
      return createResponse(200, 'Data submitted successfully', {
        submittedBy: payload.username,
        timestamp: decryptedData.submittedAt
      });
    } else {
      // שגיאה
      Logger.log('⚠️ Original script returned error: ' + responseCode);
      return createResponse(500, 'Error from data processor', null);
    }
    
  } catch (e) {
    Logger.log('❌ Error forwarding data: ' + e.toString());
    return createResponse(500, 'Error forwarding data', null);
  }
}

/**
 * קבלת נתונים קיימים
 */
function handleGetExisting(data, request) {
  const { token, personalNumber, formType } = data;
  
  // אימות Token
  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) {
    return createResponse(401, 'Invalid or expired token', null);
  }
  
  // בדיקת הרשאות
  if (!Authorization.canAccessResource(payload, formType, 'read')) {
    AuditLogger.log(payload.username, 'READ_DENIED', formType, personalNumber, 
                   { reason: 'Insufficient permissions' }, request);
    return createResponse(403, 'Insufficient permissions', null);
  }
  
  // קבלת URL של הסקריפט המקורי
  const originalScriptUrl = formType === 'weapons' 
    ? CONFIG.ORIGINAL_SCRIPTS.WEAPONS 
    : CONFIG.ORIGINAL_SCRIPTS.RADIO;
  
  if (!originalScriptUrl) {
    return createResponse(500, 'Original script URL not configured', null);
  }
  
  try {
    // שליחת בקשת GET לסקריפט המקורי
    const getUrl = originalScriptUrl + 
                   '?action=checkPersonalNumber' +
                   '&personalNumber=' + encodeURIComponent(personalNumber) + 
                   '&callback=handleResponse';
    
    Logger.log('🔍 Fetching from: ' + getUrl);
    
    const response = UrlFetchApp.fetch(getUrl, {
      method: 'get',
      muteHttpExceptions: true
    });
    
    const responseCode = response.getResponseCode();
    const responseText = response.getContentText();
    
    if (responseCode >= 200 && responseCode < 300) {
      // פענוח תשובת JSONP
      let jsonData;
      try {
        const jsonMatch = responseText.match(/handleResponse\((.*)\)/);
        if (jsonMatch && jsonMatch[1]) {
          jsonData = JSON.parse(jsonMatch[1]);
        } else {
          jsonData = JSON.parse(responseText);
        }
      } catch (parseError) {
        Logger.log('⚠️ Could not parse response');
        return createResponse(404, 'No existing data found', null);
      }
      
      if (jsonData && jsonData.exists) {
        // הצפן את הנתונים לפני שליחה חזרה
        const encryptedData = EncryptedDataHandler.encrypt(jsonData.data, CONFIG.JWT_SECRET);
        
        // רישום
        AuditLogger.log(
          payload.username,
          'DATA_RETRIEVED',
          formType,
          personalNumber,
          { action: 'get_existing', found: true },
          request
        );
        
        return createResponse(200, 'Data found', {
          data: encryptedData
        });
      } else {
        Logger.log('ℹ️ No existing data for: ' + personalNumber);
        return createResponse(404, 'No existing data found', null);
      }
      
    } else {
      Logger.log('⚠️ Original script error: ' + responseCode);
      return createResponse(500, 'Error fetching data', null);
    }
    
  } catch (e) {
    Logger.log('❌ Error fetching data: ' + e.toString());
    return createResponse(500, 'Error fetching data', null);
  }
}

/**
 * יצירת משתמש חדש
 */
function handleCreateUser(data, request) {
  const { token, userData } = data;
  
  // אימות Token
  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) {
    return createResponse(401, 'Invalid or expired token', null);
  }
  
  // רק Admin יכול ליצור משתמשים
  if (!Authorization.canAccessResource(payload, 'users', 'manage_users')) {
    return createResponse(403, 'Only admins can create users', null);
  }
  
  try {
    UserManager.createUser(userData);
    
    AuditLogger.log(
      payload.username,
      'USER_CREATED',
      'USER_MANAGEMENT',
      null,
      { newUser: userData.username, role: userData.role },
      request
    );
    
    return createResponse(200, 'User created successfully', null);
    
  } catch (e) {
    return createResponse(500, 'Error creating user', null);
  }
}

// ================================================================
// פונקציות עזר
// ================================================================

/**
 * יצירת תשובה סטנדרטית
 */
function createResponse(statusCode, message, data) {
  const response = {
    statusCode: statusCode,
    message: message,
    data: data,
    timestamp: new Date().toISOString()
  };
  
  return ContentService
    .createTextOutput(JSON.stringify(response))
    .setMimeType(ContentService.MimeType.JSON);
}

// ================================================================
// פונקציות אתחול ובדיקה
// ================================================================

/**
 * אתחול המערכת - הרץ פעם אחת!
 */
function initializeSystem() {
  Logger.log('🚀 Initializing system...');
  
  // אתחול גיליון משתמשים
  UserManager.initializeUsersSheet();
  
  // אתחול Audit Log
  AuditLogger.initializeAuditSheet();
  
  Logger.log('✅ System initialized successfully!');
  Logger.log('📝 Default admin user: admin / admin123');
}

/**
 * בדיקת חיבור
 */
function testConnection() {
  Logger.log('🧪 Testing system...');
  
  try {
    // בדיקת גישה לשיטס
    const usersSheet = UserManager.getUsersSheet();
    Logger.log('✅ Users sheet accessible');
    
    const auditSheet = AuditLogger.getAuditSheet();
    Logger.log('✅ Audit sheet accessible');
    
    // בדיקת JWT
    const testPayload = { username: 'test', role: 'user' };
    const token = JWTUtil.sign(testPayload, CONFIG.JWT_SECRET);
    const verified = JWTUtil.verify(token, CONFIG.JWT_SECRET);
    
    if (verified && verified.username === 'test') {
      Logger.log('✅ JWT working correctly');
    } else {
      Logger.log('❌ JWT verification failed');
    }
    
    Logger.log('✅ All systems operational!');
    
  } catch (e) {
    Logger.log('❌ Test failed: ' + e.toString());
  }
}