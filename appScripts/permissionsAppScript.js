/**
 * Backend Authentication & Authorization System
 * Google Apps Script implementation
 * 
 * Deploy this as a Web App in Google Apps Script
 */

// ============================================================
// CONFIGURATION - EDIT THESE VALUES
// ============================================================

const CONFIG = {
    // JWT Secret - Change this to a random string!
    JWT_SECRET: 'BagadHatzamKomando8219SecretKey2026XyZ_STATIC_2026',
    
    // Token expiration (in seconds)
    TOKEN_EXPIRATION: 3600, // 1 hour
    
    // Google Sheet IDs
    SHEETS: {
      WEAPONS: '1kPB-CL0dY7J-J_-KmOYvLUNc9Zw4vJhDYij_SOwRJN0',
      RADIO: '1jUDDvC2PPYOcEWHgb2fc5Jds_K_YYhjveHYIgAurEBc',
      USERS: '1x3QU2_6DJmOsBybj6zxAPKhJGFs84NGxruNMjDstz7E',
      AUDIT_LOG: '16dqeWkWk3KQYJzQYB7AhUhgJsHhR_7wXjAGVScaQ7Ks'
    },
    
    // Original Scripts URLs (for forwarding data after authentication)
    ORIGINAL_SCRIPTS: {
      WEAPONS: 'https://script.google.com/macros/s/AKfycby_vOgDCI8ZHR3sH42fMkXpDuCljYrpgZ3SO7YgnC97Yg0Rsm3y0P_uj0VNpnYo12Xg/exec',
      RADIO: 'https://script.google.com/macros/s/AKfycbxG1ymau8BHFFzIyqPqqe-jSIEZgc00SHoV4LMANhQbBRDm45U0RK1Ajh6m0Xcn099X/exec'
    },
    
    // User roles and permissions
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
        permissions: ['write'] // Can only submit their own data
      }
    }
  };
  
  // ============================================================
  // JWT UTILITIES
  // ============================================================
  
  /**
   * Simple HMAC-SHA256 based JWT implementation
   */
  class JWTUtil {
    static base64UrlEncode(str) {
      const base64 = Utilities.base64Encode(str);
      return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    
    static base64UrlDecode(str) {
      let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4) {
        base64 += '=';
      }
      return Utilities.base64Decode(base64);
    }
    
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
    
    static verify(token, secret) {
      try {
        const parts = token.split('.');
        if (parts.length !== 3) {
          return null;
        }
        
        const [headerEncoded, payloadEncoded, signature] = parts;
        const expectedSignature = this.createSignature(headerEncoded + '.' + payloadEncoded, secret);
        
        if (signature !== expectedSignature) {
          return null;
        }
        
        const payload = JSON.parse(Utilities.newBlob(this.base64UrlDecode(payloadEncoded)).getDataAsString());
        
        // Check expiration
        if (payload.exp && payload.exp < Date.now() / 1000) {
          return null;
        }
        
        return payload;
      } catch (e) {
        Logger.log('JWT verification error: ' + e.toString());
        return null;
      }
    }
    
    static createSignature(data, secret) {
      const signature = Utilities.computeHmacSha256Signature(data, secret);
      return this.base64UrlEncode(signature);
    }
  }
  
  // ============================================================
  // USER MANAGEMENT
  // ============================================================
  
  class UserManager {
    static getUsersSheet() {
      const ss = SpreadsheetApp.openById(CONFIG.SHEETS.USERS);
      return ss.getSheetByName('Users') || ss.insertSheet('Users');
    }
    
    static initializeUsersSheet() {
      const sheet = this.getUsersSheet();
      const lastRow = sheet.getLastRow();
      
      // If sheet is completely empty or only has headers
      if (lastRow === 0) {
        // Add headers
        sheet.appendRow(['Username', 'Password Hash', 'Role', 'Personal Number', 'Full Name', 'Email', 'Created At', 'Last Login']);
        
        // Add default admin user (password: admin123)
        const adminHash = this.hashPassword('admin123');
        sheet.appendRow(['admin', adminHash, 'admin', '', 'System Admin', '', new Date().toISOString(), '']);
        
        Logger.log('Users sheet initialized with admin user');
      } else if (lastRow === 1) {
        // Has headers but no users - add admin
        const adminHash = this.hashPassword('admin123');
        sheet.appendRow(['admin', adminHash, 'admin', '', 'System Admin', '', new Date().toISOString(), '']);
        
        Logger.log('Admin user added to existing sheet');
      }
    }
    
    static hashPassword(password) {
      // Simple hash - in production use better hashing
      const hash = Utilities.base64Encode(
        Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password + CONFIG.JWT_SECRET)
      );
      // Prevent formula injection by adding a space prefix if starts with =
      return hash.charAt(0) === '=' ? ' ' + hash : hash;
    }
    
    static authenticate(username, password) {
      const sheet = this.getUsersSheet();
      const data = sheet.getDataRange().getValues();
      
      const passwordHash = this.hashPassword(password);
      
      for (let i = 1; i < data.length; i++) {
        if (data[i][0] === username && data[i][1] === passwordHash) {
          // Update last login
          sheet.getRange(i + 1, 8).setValue(new Date().toISOString());
          
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
  
  // ============================================================
  // AUDIT LOG
  // ============================================================
  
  class AuditLogger {
    static getAuditSheet() {
      const ss = SpreadsheetApp.openById(CONFIG.SHEETS.AUDIT_LOG);
      return ss.getSheetByName('Audit Log') || ss.insertSheet('Audit Log');
    }
    
    static initializeAuditSheet() {
      const sheet = this.getAuditSheet();
      if (sheet.getLastRow() === 0) {
        sheet.appendRow([
          'Timestamp',
          'Username',
          'Action',
          'Resource',
          'Personal Number',
          'Details',
          'IP Address',
          'User Agent'
        ]);
      }
    }
    
    static log(username, action, resource, personalNumber, details, request) {
      try {
        const sheet = this.getAuditSheet();
        
        const ipAddress = request.parameter.ip || 
                         request.headers['X-Forwarded-For'] || 
                         request.headers['Remote-Addr'] || 
                         'Unknown';
        
        const userAgent = request.headers['User-Agent'] || 'Unknown';
        
        sheet.appendRow([
          new Date().toISOString(),
          username,
          action,
          resource,
          personalNumber || '',
          JSON.stringify(details),
          ipAddress,
          userAgent
        ]);
      } catch (e) {
        Logger.log('Audit log error: ' + e.toString());
      }
    }
  }
  
  // ============================================================
  // AUTHORIZATION
  // ============================================================
  
  class Authorization {
    static hasPermission(user, permission) {
      const userRole = CONFIG.ROLES[user.role.toUpperCase()];
      if (!userRole) return false;
      
      return userRole.permissions.includes(permission);
    }
    
    static canAccessResource(user, resource, action) {
      // Admin can do everything
      if (user.role === 'admin') return true;
      
      // Check specific permissions
      switch (action) {
        case 'view_reports':
          return this.hasPermission(user, 'view_reports');
        
        case 'submit':
          return this.hasPermission(user, 'write');
        
        case 'read':
          return this.hasPermission(user, 'read');
        
        case 'delete':
          return this.hasPermission(user, 'delete');
        
        default:
          return false;
      }
    }
  }
  
  // ============================================================
  // ENCRYPTED DATA HANDLER
  // ============================================================
  
  class EncryptedDataHandler {
    static encrypt(data, key) {
      try {
        // Simple XOR encryption
        const jsonStr = JSON.stringify(data);
        let encrypted = '';
        
        for (let i = 0; i < jsonStr.length; i++) {
          encrypted += String.fromCharCode(
            jsonStr.charCodeAt(i) ^ key.charCodeAt(i % key.length)
          );
        }
        
        // Use URL encoding for Unicode support
        const urlEncoded = encodeURIComponent(encrypted);
        return Utilities.base64Encode(urlEncoded);
        
      } catch (e) {
        Logger.log('Encrypt error: ' + e.toString());
        throw new Error('Encryption failed: ' + e.toString());
      }
    }
    
    static decrypt(encryptedData, key) {
      try {
        Logger.log('🔓 Starting decryption...');
        Logger.log('Encrypted data length: ' + encryptedData.length);
        Logger.log('First 50 chars: ' + encryptedData.substring(0, 50));
        
        // Decode base64 - use regular base64Decode
        let decoded;
        try {
          decoded = Utilities.base64Decode(encryptedData);
          Logger.log('✅ Base64 decoded successfully');
        } catch (b64Error) {
          Logger.log('❌ Base64 decode failed: ' + b64Error.toString());
          throw b64Error;
        }
        
        const decodedStr = Utilities.newBlob(decoded).getDataAsString();
        Logger.log('✅ Converted to string, length: ' + decodedStr.length);
        Logger.log('First 50 chars of decoded: ' + decodedStr.substring(0, 50));
        
        // Decode URI component
        let urlDecoded;
        try {
          urlDecoded = decodeURIComponent(decodedStr);
          Logger.log('✅ URL decoded, length: ' + urlDecoded.length);
        } catch (urlError) {
          Logger.log('❌ URL decode failed: ' + urlError.toString());
          throw urlError;
        }
        
        // XOR decrypt
        let decrypted = '';
        for (let i = 0; i < urlDecoded.length; i++) {
          decrypted += String.fromCharCode(
            urlDecoded.charCodeAt(i) ^ key.charCodeAt(i % key.length)
          );
        }
        
        Logger.log('✅ XOR decrypted, length: ' + decrypted.length);
        Logger.log('Decrypted preview: ' + decrypted.substring(0, 100));
        
        const parsed = JSON.parse(decrypted);
        Logger.log('✅ JSON parsed successfully');
        
        return parsed;
        
      } catch (e) {
        Logger.log('❌ Decrypt error: ' + e.toString());
        Logger.log('Error type: ' + e.name);
        Logger.log('Error message: ' + e.message);
        Logger.log('Error stack: ' + (e.stack || 'No stack trace'));
        throw new Error('Decryption failed: ' + e.toString());
      }
    }
  }
  
  // ============================================================
  // MAIN WEB APP HANDLERS
  // ============================================================
  
  function doGet(e) {
    // Handle CORS preflight
    return ContentService
      .createTextOutput(JSON.stringify({
        status: 'ok',
        message: 'Authentication API is running',
        version: '1.0.0'
      }))
      .setMimeType(ContentService.MimeType.JSON);
  }
  
  function doPost(e) {
    try {
      // Log incoming request for debugging
      Logger.log('=== NEW REQUEST ===');
      Logger.log('e.parameter: ' + JSON.stringify(e.parameter));
      Logger.log('e.postData: ' + (e.postData ? 'exists' : 'null'));
      if (e.postData) {
        Logger.log('e.postData.contents length: ' + (e.postData.contents ? e.postData.contents.length : 'null'));
      }
      
      // Initialize sheets if needed
      try {
        UserManager.initializeUsersSheet();
        AuditLogger.initializeAuditSheet();
      } catch (initError) {
        Logger.log('Initialization error: ' + initError.toString());
      }
      
      // Parse request data
      let requestData;
      try {
        // Check if data comes from parameter (form-encoded)
        if (e.parameter && e.parameter.data) {
          Logger.log('✅ Parsing from URL-encoded parameter');
          Logger.log('Raw parameter.data: ' + e.parameter.data.substring(0, 100) + '...');
          requestData = JSON.parse(decodeURIComponent(e.parameter.data));
          Logger.log('✅ Parsed action: ' + requestData.action);
        } 
        // Check if data comes from postData (JSON)
        else if (e.postData && e.postData.contents) {
          Logger.log('✅ Parsing from postData.contents');
          requestData = JSON.parse(e.postData.contents);
          Logger.log('✅ Parsed action: ' + requestData.action);
        } 
        // Fallback to parameter object
        else if (e.parameter) {
          Logger.log('⚠️ Using parameter directly');
          requestData = e.parameter;
          Logger.log('Action: ' + requestData.action);
        } 
        else {
          Logger.log('❌ No data found in request');
          return createResponse(400, 'No data received', null);
        }
      } catch (parseError) {
        Logger.log('❌ Parse error: ' + parseError.toString());
        return createResponse(400, 'Invalid data format: ' + parseError.toString(), null);
      }
      
      const action = requestData.action;
      Logger.log('📋 Final action: ' + action);
      
      // Handle different actions
      switch (action) {
        case 'login':
          return handleLogin(requestData, e);
        
        case 'verify_token':
          return handleVerifyToken(requestData, e);
        
        case 'submit_data':
          Logger.log('🎯 Handling submit_data');
          return handleSubmitData(requestData, e);
        
        case 'get_existing':
          return handleGetExisting(requestData, e);
        
        case 'create_user':
          return handleCreateUser(requestData, e);
        
        default:
          Logger.log('❌ Unknown action: ' + action);
          return createResponse(400, 'Unknown action: ' + action, null);
      }
      
    } catch (error) {
      Logger.log('❌ Error in doPost: ' + error.toString());
      Logger.log('Error stack: ' + error.stack);
      return createResponse(500, 'Server error: ' + error.toString(), null);
    }
  }
  
  // ============================================================
  // REQUEST HANDLERS
  // ============================================================
  
  function handleLogin(data, request) {
    const { username, password } = data;
    
    if (!username || !password) {
      return createResponse(400, 'Username and password required', null);
    }
    
    const user = UserManager.authenticate(username, password);
    
    if (!user) {
      AuditLogger.log(username, 'LOGIN_FAILED', 'AUTH', null, { reason: 'Invalid credentials' }, request);
      return createResponse(401, 'Invalid credentials', null);
    }
    
    // Create JWT token
    const payload = {
      username: user.username,
      role: user.role,
      personalNumber: user.personalNumber,
      fullName: user.fullName,
      email: user.email,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + CONFIG.TOKEN_EXPIRATION
    };
    
    const token = JWTUtil.sign(payload, CONFIG.JWT_SECRET);
    
    AuditLogger.log(username, 'LOGIN_SUCCESS', 'AUTH', user.personalNumber, { role: user.role }, request);
    
    return createResponse(200, 'Login successful', {
      token: token,
      user: {
        username: user.username,
        role: user.role,
        fullName: user.fullName,
        permissions: CONFIG.ROLES[user.role.toUpperCase()].permissions
      }
    });
  }
  
  function handleVerifyToken(data, request) {
    const { token } = data;
    
    if (!token) {
      return createResponse(400, 'Token required', null);
    }
    
    const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
    
    if (!payload) {
      return createResponse(401, 'Invalid or expired token', null);
    }
    
    return createResponse(200, 'Token valid', {
      user: {
        username: payload.username,
        role: payload.role,
        fullName: payload.fullName
      }
    });
  }
  
  function handleSubmitData(data, request) {
    const { token, formData, formType } = data;
    
    // Verify token
    const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
    if (!payload) {
      return createResponse(401, 'Invalid or expired token', null);
    }
    
    // Check permissions
    if (!Authorization.canAccessResource(payload, formType, 'submit')) {
      AuditLogger.log(payload.username, 'SUBMIT_DENIED', formType, formData.personalNumber, 
                     { reason: 'Insufficient permissions' }, request);
      return createResponse(403, 'Insufficient permissions', null);
    }
    
    // Decrypt form data
    let decryptedData;
    try {
      decryptedData = EncryptedDataHandler.decrypt(formData, CONFIG.JWT_SECRET);
      Logger.log('✅ Data decrypted successfully');
    } catch (e) {
      Logger.log('❌ Decryption error: ' + e.toString());
      return createResponse(400, 'Invalid encrypted data: ' + e.toString(), null);
    }
    
    // Add metadata
    decryptedData.submittedBy = payload.username;
    decryptedData.submittedAt = new Date().toISOString();
    
    // Get original script URL
    const originalScriptUrl = formType === 'weapons' 
      ? CONFIG.ORIGINAL_SCRIPTS.WEAPONS 
      : CONFIG.ORIGINAL_SCRIPTS.RADIO;
    
    if (!originalScriptUrl) {
      return createResponse(500, 'Original script URL not configured for ' + formType, null);
    }
    
    try {
      Logger.log('📤 Forwarding to original script: ' + originalScriptUrl);
      Logger.log('📦 Data size: ' + JSON.stringify(decryptedData).length + ' bytes');
      
      // Forward the decrypted data to the original script via POST
      const response = UrlFetchApp.fetch(originalScriptUrl, {
        method: 'post',
        contentType: 'application/json',
        payload: JSON.stringify(decryptedData),
        muteHttpExceptions: true
      });
      
      const responseCode = response.getResponseCode();
      const responseText = response.getContentText();
      
      Logger.log('📥 Original script response code: ' + responseCode);
      Logger.log('📥 Original script response: ' + responseText.substring(0, 200));
      
      if (responseCode >= 200 && responseCode < 300) {
        // Success!
        Logger.log('✅ Data forwarded successfully to original script');
        
        // Log the action
        AuditLogger.log(
          payload.username, 
          'DATA_SUBMITTED', 
          formType, 
          decryptedData.personalNumber,
          { 
            action: 'submit', 
            dataSize: JSON.stringify(decryptedData).length,
            forwardedTo: originalScriptUrl
          },
          request
        );
        
        return createResponse(200, 'Data submitted successfully', {
          submittedBy: payload.username,
          timestamp: decryptedData.submittedAt,
          message: 'Data processed and saved'
        });
        
      } else {
        // Error from original script
        Logger.log('⚠️ Original script returned error: ' + responseCode);
        return createResponse(500, 'Error from data processor: ' + responseText, null);
      }
      
    } catch (e) {
      Logger.log('❌ Error forwarding to original script: ' + e.toString());
      return createResponse(500, 'Error forwarding data: ' + e.toString(), null);
    }
  }
  
  function handleGetExisting(data, request) {
    const { token, personalNumber, formType } = data;
    
    // Verify token
    const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
    if (!payload) {
      return createResponse(401, 'Invalid or expired token', null);
    }
    
    // Check permissions
    if (!Authorization.canAccessResource(payload, formType, 'read')) {
      AuditLogger.log(payload.username, 'READ_DENIED', formType, personalNumber, 
                     { reason: 'Insufficient permissions' }, request);
      return createResponse(403, 'Insufficient permissions', null);
    }
    
    // Get original script URL
    const originalScriptUrl = formType === 'weapons' 
      ? CONFIG.ORIGINAL_SCRIPTS.WEAPONS 
      : CONFIG.ORIGINAL_SCRIPTS.RADIO;
    
    if (!originalScriptUrl) {
      return createResponse(500, 'Original script URL not configured for ' + formType, null);
    }
    
    try {
      // Use GET with proper parameters for the old script
      const getUrl = originalScriptUrl + 
                     '?action=checkPersonalNumber' +
                     '&personalNumber=' + encodeURIComponent(personalNumber) + 
                     '&callback=handleResponse';
      
      Logger.log('🔍 Fetching existing data from: ' + getUrl);
      
      const response = UrlFetchApp.fetch(getUrl, {
        method: 'get',
        muteHttpExceptions: true
      });
      
      const responseCode = response.getResponseCode();
      const responseText = response.getContentText();
      
      Logger.log('📥 Original script response code: ' + responseCode);
      Logger.log('📥 Original script response: ' + responseText.substring(0, 500));
      
      if (responseCode >= 200 && responseCode < 300) {
        // Parse JSONP response
        // Expected format: handleResponse({...})
        let jsonData;
        try {
          // Extract JSON from JSONP wrapper
          const jsonMatch = responseText.match(/handleResponse\((.*)\)/);
          if (jsonMatch && jsonMatch[1]) {
            jsonData = JSON.parse(jsonMatch[1]);
          } else {
            // Maybe it's already JSON?
            jsonData = JSON.parse(responseText);
          }
        } catch (parseError) {
          Logger.log('⚠️ Could not parse response: ' + parseError.toString());
          return createResponse(404, 'No existing data found', null);
        }
        
        if (jsonData && jsonData.exists) {
          // Encrypt the data before sending back
          const encryptedData = EncryptedDataHandler.encrypt(jsonData.data, CONFIG.JWT_SECRET);
          
          // Log the action
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
          // No data found
          Logger.log('ℹ️ No existing data for personal number: ' + personalNumber);
          return createResponse(404, 'No existing data found', null);
        }
        
      } else {
        Logger.log('⚠️ Original script returned error: ' + responseCode);
        return createResponse(500, 'Error fetching data: ' + responseText, null);
      }
      
    } catch (e) {
      Logger.log('❌ Error fetching data: ' + e.toString());
      return createResponse(500, 'Error fetching data: ' + e.toString(), null);
    }
  }
  
  function handleCreateUser(data, request) {
    const { token, userData } = data;
    
    // Verify token
    const payload = JWTUtil.verify(token, CONFIG.JWT_SECRET);
    if (!payload) {
      return createResponse(401, 'Invalid or expired token', null);
    }
    
    // Only admins can create users
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
      return createResponse(500, 'Error creating user: ' + e.toString(), null);
    }
  }
  
  // ============================================================
  // UTILITY FUNCTIONS
  // ============================================================
  
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