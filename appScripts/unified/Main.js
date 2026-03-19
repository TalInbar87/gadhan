/**
 * ================================================================
 * Main Entry Point - נקודת כניסה ראשית
 * ================================================================
 *
 * פרויקט מאוחד: Permissions + Weapons + Radio → GAS אחד בלבד
 *
 * יתרונות לעומת ארכיטקטורת 3 סקריפטים נפרדים:
 * ✓ ללא UrlFetchApp.fetch() בין סקריפטים
 * ✓ ללא הצפנת XOR בין הסקריפטים (נשמר רק לדפדפן↔שרת)
 * ✓ URL יחיד ויציב לכל הפעולות
 * ✓ שגיאות מרוכזות ב-Logger יחיד
 *
 * הוראות פריסה (פעם ראשונה):
 * 1. צור Google Apps Script חדש (Standalone - לא קשור לשום Sheet)
 *    https://script.google.com → New project
 * 2. צור 6 קבצים: Config.js, Utils.js, Auth.js, Weapons.js, Radio.js, Main.js
 *    (אפשר להשתמש ב-clasp push אם יש scriptId ב-.clasp.json)
 * 3. הרץ initializeSystem() פעם אחת (גורם לאישור הרשאות)
 * 4. Deploy → New deployment → Web app
 *    - Execute as: Me
 *    - Who has access: Anyone
 * 5. העתק את ה-URL החדש → עדכן API_URL בכל קבצי ה-HTML
 *
 * ================================================================
 */

// ================================================================
// HTTP Entry Points
// ================================================================

/**
 * בקשות GET - בדיקת קיום מספר אישי בגיליון נשקים/קשר
 * Query params: action=checkPersonalNumber&personalNumber=X&formType=weapons|radio&callback=cb
 */
function doGet(e) {
  try {
    if (!e || !e.parameter) {
      return createJsonpResponse({ error: 'No parameters' }, 'callback');
    }

    const action       = e.parameter.action;
    const personalNumber = e.parameter.personalNumber;
    const formType     = e.parameter.formType;
    const callback     = e.parameter.callback || 'callback';

    if (action === 'checkPersonalNumber') {
      return formType === 'radio'
        ? radio_checkPersonalNumber(personalNumber, callback)
        : weapons_checkPersonalNumber(personalNumber, callback);
    }

    return createJsonpResponse({ error: 'Unknown action: ' + action }, callback);

  } catch (err) {
    const cb = (e && e.parameter && e.parameter.callback) || 'callback';
    Logger.log('❌ doGet error: ' + err);
    return createJsonpResponse({ error: err.toString() }, cb);
  }
}

/**
 * בקשות POST - כל הפעולות
 */
function doPost(e) {
  try {
    Logger.log('🎯 doPost called');

    if (!e) return createResponse(400, 'No request data', null);

    const data = parsePostData(e);
    if (!data) {
      Logger.log('❌ All parse attempts failed. postData: ' + JSON.stringify(e.postData));
      Logger.log('parameter: ' + JSON.stringify(e.parameter));
      return createResponse(400, 'No data provided', null);
    }

    Logger.log('▶ Action: ' + data.action);

    switch (data.action) {
      case 'login':          return handleLogin(data, e);
      case 'verify_token':   return handleVerifyToken(data, e);
      case 'submit_data':    return handleSubmitData(data, e);
      case 'get_existing':   return handleGetExisting(data, e);
      case 'create_user':    return handleCreateUser(data, e);
      case 'credit_data':    return handleCreditData(data, e);
      case 'partial_credit': return handlePartialCredit(data, e);
      case 'transfer_items': return handleTransferItems(data, e);
      case 'swap_items':     return handleSwapItems(data, e);
      case 'get_audit_log':        return handleGetAuditLog(data, e);
      case 'get_weapons_inventory': return handleGetWeaponsInventory(data, e);
      case 'get_armory_count':     return handleGetArmoryCount(data, e);
      case 'save_armory_count':    return handleSaveArmoryCount(data, e);
      default:                     return createResponse(400, 'Unknown action: ' + data.action, null);
    }

  } catch (err) {
    Logger.log('❌ doPost error: ' + err + '\n' + (err.stack || ''));
    return createResponse(500, 'Server error: ' + err.toString(), null);
  }
}

// ================================================================
// Auth Handlers
// ================================================================

function handleLogin(data, request) {
  const { username, password } = data;
  Logger.log('🔐 Login attempt: ' + username);

  const user = UserManager.authenticate(username, password);
  if (!user) {
    AuditLogger.log(username, 'LOGIN_FAILED', 'AUTH', null, { reason: 'Invalid credentials' }, request);
    return createResponse(401, 'Invalid username or password', null);
  }

  const payload = {
    username:       user.username,
    role:           user.role,
    personalNumber: user.personalNumber,
    fullName:       user.fullName,
    email:          user.email,
    permissions:    Authorization.getPermissions(user.role),
    iat:            Math.floor(Date.now() / 1000),
    exp:            Math.floor(Date.now() / 1000) + CONFIG.TOKEN_EXPIRATION
  };

  const token = JWTUtil.sign(payload, CONFIG.JWT_SECRET);
  AuditLogger.log(username, 'LOGIN_SUCCESS', 'AUTH', null, { role: user.role }, request);
  Logger.log('✅ Login OK: ' + username);

  return createResponse(200, 'Login successful', {
    token,
    user: {
      username:       user.username,
      role:           user.role,
      personalNumber: user.personalNumber,
      fullName:       user.fullName,
      email:          user.email,
      permissions:    Authorization.getPermissions(user.role)
    }
  });
}

function handleVerifyToken(data, request) {
  const payload = JWTUtil.verify(data.token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);
  return createResponse(200, 'Token is valid', {
    user: { username: payload.username, role: payload.role, permissions: payload.permissions }
  });
}

// ================================================================
// Data Handlers — ישיר לגיליון (ללא HTTP)
// ================================================================

/**
 * שליחת נתוני טופס - מפענח ושומר ישירות לגיליון המתאים
 */
function handleSubmitData(data, request) {
  const { token, formData, formType } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  if (!Authorization.canAccessResource(payload, formType, 'submit')) {
    AuditLogger.log(payload.username, 'SUBMIT_DENIED', formType, null,
                   { reason: 'Insufficient permissions' }, request);
    return createResponse(403, 'Insufficient permissions', null);
  }

  let decryptedData;
  try {
    decryptedData = EncryptedDataHandler.decrypt(formData, CONFIG.JWT_SECRET);
  } catch (e) {
    Logger.log('❌ Decryption error: ' + e);
    return createResponse(400, 'Invalid encrypted data', null);
  }

  decryptedData.submittedBy = payload.username;
  decryptedData.submittedAt = new Date().toISOString();

  // שמור ישירות — ללא HTTP לסקריפט חיצוני
  if (formType === 'weapons') {
    weapons_saveToSheet(decryptedData);
    try { weapons_generateAndSendPDF(decryptedData); } catch(e) { Logger.log('⚠️ Email error: ' + e); }
  } else {
    radio_saveToSheet(decryptedData);
    radio_generateAndSendPDF(decryptedData);
  }

  AuditLogger.log(payload.username, 'DATA_SUBMITTED', formType,
                 decryptedData.personalNumber,
                 { signedBy: payload.fullName || payload.username }, request);

  return createResponse(200, 'Data submitted successfully', {
    submittedBy: payload.username,
    timestamp:   decryptedData.submittedAt
  });
}

/**
 * קבלת נתונים קיימים - קורא ישירות מהגיליון ומחזיר מוצפן
 */
function handleGetExisting(data, request) {
  const { token, personalNumber, formType } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  if (!Authorization.canAccessResource(payload, formType, 'read')) {
    AuditLogger.log(payload.username, 'READ_DENIED', formType, personalNumber,
                   { reason: 'Insufficient permissions' }, request);
    return createResponse(403, 'Insufficient permissions', null);
  }

  const isRadio       = formType === 'radio';
  const sheetId       = isRadio ? CONFIG.SHEETS.RADIO    : CONFIG.SHEETS.WEAPONS;
  const sheetName     = isRadio ? CONFIG.RADIO.MAIN_SHEET_NAME  : CONFIG.WEAPONS.MAIN_SHEET_NAME;
  const pnColIdx      = isRadio ? 0 : 2; // A or C (0-indexed)

  const ss        = SpreadsheetApp.openById(sheetId);
  const mainSheet = ss.getSheetByName(sheetName);
  if (!mainSheet) return createResponse(404, 'No existing data found', null);

  const rows = mainSheet.getDataRange().getDisplayValues();
  let existingData = null;

  for (let i = 1; i < rows.length; i++) {
    if (rows[i][pnColIdx] == personalNumber) {
      if (isRadio) {
        existingData = {
          personalNumber:  rows[i][0],
          fullName:        rows[i][2],
          phone:           '0' + rows[i][3],
          email:           rows[i][4],
          unit:            rows[i][5],
          radio624:        rows[i][6],
          radio91:         rows[i][7],
          hasColumn:       rows[i][8] === '1',
          columnNumber:    rows[i][9],
          amplifier:       rows[i][10],
          rigidAdapter:    rows[i][11],
          longAntenna:     rows[i][12],
          mad:             rows[i][13],
          flexibleAdapter: rows[i][14],
          shortAntenna:    rows[i][15],
          speaker:         rows[i][16],
          madona:          rows[i][17],
          apple:           rows[i][18],
          pear:            rows[i][19]
        };
      } else {
        existingData = {
          personalNumber: rows[i][2],
          fullName:       rows[i][1],
          phone:          '0' + rows[i][3],
          email:          rows[i][4],
          unit:           rows[i][5],
          team:           rows[i][6]
        };
        WEAPONS_ITEM_LIST.forEach(function(item) {
          existingData[item.key] = rows[i][item.col] || '';
        });
        // שלוף הערות מגיליון זיווד ראשי
        try {
          const zSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד');
          if (zSheet) {
            const zRows = zSheet.getDataRange().getValues();
            for (let zi = 1; zi < zRows.length; zi++) {
              if (zRows[zi][2] == personalNumber) {
                WEAPONS_ITEM_LIST.forEach(function(item) {
                  if (zRows[zi][item.col]) existingData['note_' + item.key] = zRows[zi][item.col];
                });
                break;
              }
            }
          }
        } catch(e) { Logger.log('⚠️ note fetch in getExisting: ' + e); }
      }
      break;
    }
  }

  if (!existingData) return createResponse(404, 'No existing data found', null);

  const encryptedData = EncryptedDataHandler.encrypt(existingData, CONFIG.JWT_SECRET);
  AuditLogger.log(payload.username, 'DATA_RETRIEVED', formType, personalNumber, { found: true }, request);

  return createResponse(200, 'Data found', { data: encryptedData });
}

// ================================================================
// Admin Handlers
// ================================================================

function handleCreateUser(data, request) {
  const { token, userData } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);
  if (!Authorization.canAccessResource(payload, null, 'manage_users')) return createResponse(403, 'Insufficient permissions', null);

  try {
    UserManager.createUser(userData);
    AuditLogger.log(payload.username, 'USER_CREATED', 'USER_MANAGEMENT', null,
                   { newUser: userData.username, role: userData.role }, request);
    return createResponse(200, 'User created successfully', null);
  } catch (e) {
    Logger.log('❌ createUser error: ' + e);
    return createResponse(400, e.message || 'Error creating user', null);
  }
}

/**
 * זיכוי מלא - מנהל בלבד
 */
function handleCreditData(data, request) {
  const { token, formType, creditData } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  if (!Authorization.canAccessResource(payload, formType, 'credit')) {
    AuditLogger.log(payload.username, 'CREDIT_DENIED', formType,
                   creditData.personalNumber, { reason: 'Insufficient permissions' }, request);
    return createResponse(403, 'Insufficient permissions', null);
  }

  const creditPayload = {
    personalNumber:  creditData.personalNumber,
    creditBy:        creditData.creditBy,
    creditAt:        creditData.creditAt,
    creditSignature: creditData.creditSignature
  };

  // קריאה ישירה לפונקציה — ללא HTTP
  const result = formType === 'weapons'
    ? weapons_handleCredit(creditPayload)
    : radio_handleCredit(creditPayload);

  if (result.success) {
    AuditLogger.log(payload.username, 'DATA_CREDITED', formType,
                   creditData.personalNumber,
                   { creditBy: creditData.creditBy, items: creditData.itemsWithValues || [] }, request);
    return createResponse(200, 'Credit completed successfully', null);
  }
  return createResponse(500, result.error || 'Credit failed', null);
}

/**
 * זיכוי חלקי - נשקים בלבד (מנהל)
 */
function handlePartialCredit(data, request) {
  const { token, formType, creditData } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  if (!Authorization.canAccessResource(payload, formType, 'credit')) {
    AuditLogger.log(payload.username, 'PARTIAL_CREDIT_DENIED', formType,
                   creditData.personalNumber, { reason: 'Insufficient permissions' }, request);
    return createResponse(403, 'Insufficient permissions', null);
  }

  const creditPayload = {
    personalNumber:    creditData.personalNumber,
    selectedItems:     creditData.selectedItems,
    selectedNoteItems: creditData.selectedNoteItems || [],
    itemsWithValues:   creditData.itemsWithValues,
    creditBy:          creditData.creditBy,
    creditAt:          creditData.creditAt,
    creditSignature:   creditData.creditSignature
  };

  const result = formType === 'weapons'
    ? weapons_handlePartialCredit(creditPayload)
    : radio_handlePartialCredit(creditPayload);

  if (result.success) {
    AuditLogger.log(payload.username, 'DATA_PARTIAL_CREDITED', formType,
                   creditData.personalNumber,
                   { items: creditData.itemsWithValues || creditData.selectedItems, noteItems: creditData.selectedNoteItems, creditBy: creditData.creditBy }, request);
    return createResponse(200, 'Partial credit completed successfully', null);
  }
  return createResponse(500, result.error || 'Partial credit failed', null);
}

/**
 * העברת פריטים - נשקים בלבד (מנהל)
 */
function handleTransferItems(data, request) {
  const { token, formType, transferData } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  if (!Authorization.canAccessResource(payload, formType, 'transfer')) {
    AuditLogger.log(payload.username, 'TRANSFER_DENIED', formType,
                   transferData.sourcePersonalNumber, { reason: 'Insufficient permissions' }, request);
    return createResponse(403, 'Only admins can transfer equipment', null);
  }

  if (formType !== 'weapons') {
    return createResponse(400, 'Transfer is only supported for weapons', null);
  }

  const transferPayload = {
    sourcePersonalNumber: transferData.sourcePersonalNumber,
    targetPersonalNumber: transferData.targetPersonalNumber,
    selectedItems:        transferData.selectedItems,
    selectedNoteItems:    transferData.selectedNoteItems || [],
    transferBy:           transferData.transferBy,
    transferAt:           transferData.transferAt
  };

  const result = weapons_handleTransferItems(transferPayload);

  if (result.success) {
    AuditLogger.log(payload.username, 'ITEMS_TRANSFERRED', formType,
                   transferData.sourcePersonalNumber,
                   {
                     target:     transferData.targetPersonalNumber,
                     items:      transferData.selectedItems,
                     noteItems:  transferData.selectedNoteItems,
                     transferBy: transferData.transferBy
                   }, request);
    return createResponse(200, 'Transfer completed successfully', null);
  }
  return createResponse(500, result.error || 'Transfer failed', null);
}

/**
 * ראש בראש — החלפת מספרי סידורי של אותו סוג ציוד בין שני חיילים
 * נגיש לכל משתמש מאומת
 */
function handleSwapItems(data, request) {
  const { token, swapData } = data;
  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  const result = weapons_handleSwap(swapData);
  if (result.success) {
    AuditLogger.log(payload.username, 'ITEMS_SWAPPED', 'weapons',
                   swapData.sourcePN,
                   { target: swapData.targetPN, itemKey: swapData.itemKey, swapBy: swapData.swapBy }, request);
    return createResponse(200, 'Swap completed successfully', null);
  }
  return createResponse(500, result.error || 'Swap failed', null);
}

/**
 * יומן ביקורת - מנהלים בלבד
 */
function handleGetAuditLog(data, request) {
  const { token, limit } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);
  if (!Authorization.canAccessResource(payload, null, 'audit_log')) return createResponse(403, 'Insufficient permissions', null);

  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEETS.AUDIT_LOG);
    const sheet = ss.getSheetByName('Audit Log');
    if (!sheet) return createResponse(200, 'No audit data', { entries: [] });

    const rows = sheet.getDataRange().getValues();
    const entries = [];

    for (let i = 1; i < rows.length; i++) {
      entries.push({
        timestamp:      rows[i][0] ? new Date(rows[i][0]).toISOString() : '',
        username:       rows[i][1] || '',
        action:         rows[i][2] || '',
        resource:       rows[i][3] || '',
        personalNumber: rows[i][4] || '',
        details:        rows[i][5] || '',
        ip:             rows[i][6] || ''
      });
    }

    // החדש ביותר קודם
    entries.reverse();

    // הגבלת כמות רשומות (ברירת מחדל 500)
    const maxEntries = limit || 500;
    const limited = entries.slice(0, maxEntries);

    AuditLogger.log(payload.username, 'AUDIT_LOG_READ', 'AUDIT', null, { count: limited.length }, request);
    return createResponse(200, 'Audit log retrieved', { entries: limited });

  } catch (e) {
    Logger.log('❌ getAuditLog error: ' + e);
    return createResponse(500, 'Error reading audit log: ' + e.toString(), null);
  }
}

/**
 * סיכום מלאי נשקים - כמות לפי פריט ומסגרת
 */
function handleGetWeaponsInventory(data, request) {
  const { token } = data;

  const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  if (!Authorization.canAccessResource(payload, null, 'view_reports')) {
    return createResponse(403, 'Insufficient permissions', null);
  }

  try {
    const result = weapons_getInventorySummary();
    if (!result.success) return createResponse(500, result.error || 'Failed to retrieve inventory', null);

    AuditLogger.log(payload.username, 'INVENTORY_VIEWED', 'weapons', null, {}, request);
    return createResponse(200, 'Inventory summary retrieved', result.data);
  } catch (e) {
    Logger.log('❌ getWeaponsInventory error: ' + e);
    return createResponse(500, 'Error: ' + e.toString(), null);
  }
}

// ================================================================
// Armory Handlers
// ================================================================

function handleGetArmoryCount(data, request) {
  const payload = JWTUtil.verify(data.token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);
  if (!Authorization.canAccessResource(payload, null, 'view_reports')) {
    return createResponse(403, 'Insufficient permissions', null);
  }
  try {
    const result = armory_getLatestCount();
    return createResponse(200, 'Armory count retrieved', result.data);
  } catch (e) {
    Logger.log('❌ getArmoryCount error: ' + e);
    return createResponse(500, 'Error: ' + e.toString(), null);
  }
}

function handleSaveArmoryCount(data, request) {
  const payload = JWTUtil.verify(data.token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);
  if (!Authorization.canAccessResource(payload, null, 'view_reports')) {
    return createResponse(403, 'Insufficient permissions', null);
  }
  try {
    const result = armory_saveCount({
      counts:      data.counts,
      performedBy: payload.fullName || payload.username
    });
    AuditLogger.log(payload.username, 'ARMORY_COUNT_SAVED', 'armory', null,
                   { by: payload.username }, request);
    return createResponse(200, result.message, { timestamp: result.timestamp });
  } catch (e) {
    Logger.log('❌ saveArmoryCount error: ' + e);
    return createResponse(500, 'Error: ' + e.toString(), null);
  }
}

// ================================================================
// System Setup & Testing
// ================================================================

/**
 * אתחול המערכת - הרץ פעם אחת לאחר יצירת הסקריפט!
 * יוצר גיליון משתמשים עם admin ברירת מחדל (admin / admin123)
 */
function initializeSystem() {
  Logger.log('🚀 Initializing unified system...');
  UserManager.initializeUsersSheet();
  Logger.log('✅ System initialized. Default credentials: admin / admin123');
  Logger.log('⚠️  שנה את סיסמת ה-admin מיד לאחר ההתחברות הראשונה!');
}

/**
 * בדיקת חיבור לכל 4 הגיליונות + JWT
 */
function testConnection() {
  Logger.log('🧪 Testing all connections...');
  try {
    SpreadsheetApp.openById(CONFIG.SHEETS.USERS);     Logger.log('✅ Users sheet OK');
    SpreadsheetApp.openById(CONFIG.SHEETS.AUDIT_LOG); Logger.log('✅ Audit Log sheet OK');
    SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);   Logger.log('✅ Weapons sheet OK');
    SpreadsheetApp.openById(CONFIG.SHEETS.RADIO);     Logger.log('✅ Radio sheet OK');

    const t = JWTUtil.sign({ test: 1, exp: Math.floor(Date.now() / 1000) + 60 }, CONFIG.JWT_SECRET);
    const v = JWTUtil.verify(t, CONFIG.JWT_SECRET);
    if (v && v.test === 1) Logger.log('✅ JWT OK');
    else Logger.log('❌ JWT failed');

    Logger.log('✅ All systems operational!');
  } catch (err) {
    Logger.log('❌ Connection test failed: ' + err);
  }
}