/**
 * Google Apps Script for Radio Equipment Management System
 * 
 * הוראות התקנה:
 * 1. פתח Google Sheets חדש
 * 2. לחץ על Extensions > Apps Script
 * 3. מחק את הקוד הקיים והדבק את הקוד הזה
 * 4. שמור את הפרויקט (Ctrl+S)
 * 
 * *** חשוב מאוד לשליחת מיילים: ***
 * 5. בחר את הפונקציה "forcePermissions" מהתפריט הנפתח למעלה
 * 6. לחץ על כפתור ההרצה (Run/▶)
 * 7. אשר את ההרשאות כשמתבקש (צריך הרשאה לשלוח מיילים)
 * 8. רק אחרי זה המשך להתקנה
 * 
 * 9. לחץ על Deploy > New deployment
 * 10. בחר "Web app"
 * 11. Execute as: Me
 * 12. Who has access: Anyone
 * 13. לחץ Deploy
 * 14. העתק את ה-URL שתקבל והדבק ב-HTML במשתנה GOOGLE_SCRIPT_URL
 * 
 * מסגרות: פלוגה א׳, פלוגה ב׳, פלוגה ג׳, פלס״מ, ניוד, מחסר, מפג״ד
 */

/**
 * @OnlyCurrentDoc
 */

// Request necessary permissions
var SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/script.send_mail'
  ];
  
  // Force authorization - run this first!
  function requestPermissions() {
    // This function forces Google to ask for permissions
    SpreadsheetApp.getActiveSpreadsheet();
    MailApp.getRemainingDailyQuota();
    Logger.log('✅ Permissions requested. You should see authorization prompt.');
  }
  
  /**
   * Handle GET requests - used for checking if personal number exists
   */
  function doGet(e) {
    try {
      const action = e.parameter.action;
      const callback = e.parameter.callback || 'callback'; // JSONP callback
      
      if (action === 'checkPersonalNumber') {
        const personalNumber = e.parameter.personalNumber;
        Logger.log('🔍 Checking personal number: ' + personalNumber);
        
        const ss = SpreadsheetApp.getActiveSpreadsheet();
        const allRecordsSheet = ss.getSheetByName("כל הרשומות");
        
        if (!allRecordsSheet) {
          const result = JSON.stringify({ exists: false });
          return ContentService.createTextOutput(callback + '(' + result + ')')
            .setMimeType(ContentService.MimeType.JAVASCRIPT);
        }
        
        // Search for the personal number in column C (3)
        const data = allRecordsSheet.getDataRange().getValues();
        
        for (let i = 1; i < data.length; i++) { // Start from 1 to skip headers
          if (data[i][0] == personalNumber) { // Column A is index 0 (מספר אישי)
            Logger.log('✓ Found existing record at row ' + (i + 1));
            
            // Return the existing data
            const result = JSON.stringify({
              exists: true,
              data: {
                personalNumber: data[i][0],
                fullName: data[i][2],
                phone: "0" + data[i][3],
                email: data[i][4],
                unit: data[i][5],
                radio624: data[i][6],
                radio91: data[i][7],
                hasColumn: data[i][8] == "1" ? true : false,
                columnNumber: data[i][9],
                amplifier: data[i][10],
                rigidAdapter: data[i][11],
                longAntenna: data[i][12],
                mad: data[i][13],
                flexibleAdapter: data[i][14],
                shortAntenna: data[i][15],
                speaker: data[i][16],
                madona: data[i][17],
                apple: data[i][18],
                pear: data[i][19]
              }
            });
            Logger.log(result);
            return ContentService.createTextOutput(callback + '(' + result + ')')
              .setMimeType(ContentService.MimeType.JAVASCRIPT);
          }
        }
        
        Logger.log('✗ Personal number not found');
        const result = JSON.stringify({ exists: false });
        return ContentService.createTextOutput(callback + '(' + result + ')')
          .setMimeType(ContentService.MimeType.JAVASCRIPT);
      }
      
      const result = JSON.stringify({ error: 'Unknown action' });
      return ContentService.createTextOutput(callback + '(' + result + ')')
        .setMimeType(ContentService.MimeType.JAVASCRIPT);
      
    } catch (error) {
      Logger.log('❌ Error in doGet: ' + error.toString());
      const callback = e.parameter.callback || 'callback';
      const result = JSON.stringify({ error: error.toString() });
      return ContentService.createTextOutput(callback + '(' + result + ')')
        .setMimeType(ContentService.MimeType.JAVASCRIPT);
    }
  }
  
  function doPost(e) {
    try {
      Logger.log('🎯 doPost called!');
      Logger.log('📨 Raw request: ' + JSON.stringify(e));
      
      // Check if we have postData
      if (!e.postData) {
        Logger.log('❌ No postData found!');
        return ContentService.createTextOutput(JSON.stringify({
          success: false,
          error: 'No postData found'
        })).setMimeType(ContentService.MimeType.JSON);
      }
      
      Logger.log('📦 postData.contents: ' + e.postData.contents);
      
      // Parse the incoming data
      const data = JSON.parse(e.postData.contents);
      Logger.log('✅ Data parsed successfully');
      Logger.log('📥 Received data: ' + JSON.stringify(data));
      Logger.log('📧 Email field: ' + data.email);
      Logger.log('👤 Personal Number: ' + data.personalNumber);
      Logger.log('🏢 Unit: ' + data.unit);
      
      // Get the active spreadsheet
      const ss = SpreadsheetApp.getActiveSpreadsheet();
      
      // Add timestamp
      const timestamp = new Date();
      const formattedTimestamp = Utilities.formatDate(timestamp, "Asia/Jerusalem", "yyyy-MM-dd HH:mm:ss");
      Logger.log('🕐 Timestamp: ' + formattedTimestamp);
      
      // Determine which sheet to use based on unit (מסגרת)
      let sheetName = data.unit || "ללא מסגרת";
      let sheet = ss.getSheetByName(sheetName);
      
      // If sheet doesn't exist, create it
      if (!sheet) {
        sheet = ss.insertSheet(sheetName);
        
        sheet.appendRow([
          "מספר אישי",
          "תאריך ושעה",
          "שם מלא", 
          "טלפון",
          "מייל",
          "מסגרת",
          "624",
          "91",
          "עמוד",
          "מספר עמוד",
          "מגבר",
          "מתאם קשיח",
          "אנטנה לונג",
          "מעד",
          "מתאם גמיש",
          "אנטנה שורט",
          "רמק",
          "מדונה",
          "תפוח",
          "אגס"
        ]);
        
        // Format header row
        const headerRange = sheet.getRange(1, 1, 1, 20);
        headerRange.setBackground("#1e40af");
        headerRange.setFontColor("#FFFFFF");
        headerRange.setFontWeight("bold");
        headerRange.setHorizontalAlignment("right");
      }
      
      // Check if personal number already exists in this sheet
      const personalNumberCol = 1; // Column A (מספר אישי)
      const lastRow = sheet.getLastRow();
      let existingRow = null;
      
      if (lastRow > 1) { // If there are records beyond the header
        const personalNumbers = sheet.getRange(2, personalNumberCol, lastRow - 1, 1).getValues();
        for (let i = 0; i < personalNumbers.length; i++) {
          if (personalNumbers[i][0].toString() === data.personalNumber.toString()) {
            existingRow = i + 2; // +2 because array is 0-indexed and we start from row 2
            break;
          }
        }
      }
      
      // Prepare row data - separate column for each equipment type
      const rowData = [
        data.personalNumber,
        formattedTimestamp,
        data.fullName,
        data.phone,
        data.email,
        data.unit || "",
        data.radio624 || "",
        data.radio91 || "",
        data.hasColumn ? "1" : "",
        data.columnNumber || "",
        data.amplifier || "",
        data.rigidAdapter || "",
        data.longAntenna || "",
        data.mad || "",
        data.flexibleAdapter || "",
        data.shortAntenna || "",
        data.speaker || "",
        data.madona || "",
        data.apple || "",
        data.pear || ""
      ];
      
      if (existingRow) {
        // Update existing row
        sheet.getRange(existingRow, 1, 1, 20).setValues([rowData]);
      } else {
        // Add new row
        sheet.appendRow(rowData);
      }
      
      // Also handle "כל הרשומות" sheet
      let allRecordsSheet = ss.getSheetByName("כל הרשומות");
      if (!allRecordsSheet) {
        allRecordsSheet = ss.insertSheet("כל הרשומות");
        // Add headers
        allRecordsSheet.appendRow([
          "מספר אישי",
          "תאריך ושעה",
          "שם מלא",
          "טלפון",
          "מייל",
          "מסגרת",
          "624",
          "91",
          "עמוד",
          "מספר עמוד",
          "מגבר",
          "מתאם קשיח",
          "אנטנה לונג",
          "מעד",
          "מתאם גמיש",
          "אנטנה שורט",
          "רמק",
          "מדונה",
          "תפוח",
          "אגס"
        ]);
        
        // Format header row
        const headerRange = allRecordsSheet.getRange(1, 1, 1, 20);
        headerRange.setBackground("#1e40af");
        headerRange.setFontColor("#FFFFFF");
        headerRange.setFontWeight("bold");
        headerRange.setHorizontalAlignment("right");
      }
      
      // Check if personal number exists in "כל הרשומות"
      const allRecordsLastRow = allRecordsSheet.getLastRow();
      let existingRowInAll = null;
      
      if (allRecordsLastRow > 1) {
        const allPersonalNumbers = allRecordsSheet.getRange(2, personalNumberCol, allRecordsLastRow - 1, 1).getValues();
        for (let i = 0; i < allPersonalNumbers.length; i++) {
          if (allPersonalNumbers[i][0].toString() === data.personalNumber.toString()) {
            existingRowInAll = i + 2;
            break;
          }
        }
      }
      
      if (existingRowInAll) {
        // Update existing row in "כל הרשומות"
        allRecordsSheet.getRange(existingRowInAll, 1, 1, 20).setValues([rowData]);
      } else {
        // Add new row to "כל הרשומות"
        allRecordsSheet.appendRow(rowData);
      }
      
      // Auto-resize columns for better readability
      sheet.autoResizeColumns(1, 20);
      allRecordsSheet.autoResizeColumns(1, 20);
      
      Logger.log('✅ Data saved to sheets successfully');
      
      // Generate PDF and send email if email is provided
      if (data.email && data.email.trim() !== "") {
        Logger.log('📧 Email provided: ' + data.email);
        Logger.log('✉️ Attempting to send PDF...');
        try {
          generateAndSendPDF(data, formattedTimestamp);
          Logger.log('✅ PDF sent successfully!');
        } catch (pdfError) {
          Logger.log('❌ PDF Error: ' + pdfError.toString());
          Logger.log('❌ Error stack: ' + pdfError.stack);
          // Continue even if PDF fails - don't block the form submission
        }
      } else {
        Logger.log('⚠️ No email provided - skipping PDF generation');
        Logger.log('Email field value: "' + data.email + '"');
      }
      
      // Return success response with update info
      return ContentService.createTextOutput(JSON.stringify({
        'result': 'success',
        'action': existingRow ? 'updated' : 'created',
        'row': existingRow || sheet.getLastRow(),
        'pdfSent': (data.email && data.email.trim() !== "") ? true : false
      })).setMimeType(ContentService.MimeType.JSON);
      
    } catch (error) {
      Logger.log('❌ Error in doPost: ' + error.toString());
      // Return error response
      return ContentService.createTextOutput(JSON.stringify({
        'result': 'error',
        'error': error.toString()
      })).setMimeType(ContentService.MimeType.JSON);
    }
  }
  
  function generateAndSendPDF(data, timestamp) {
    Logger.log('🎯 generateAndSendPDF started');
    Logger.log('📧 Recipient email: ' + data.email);
    Logger.log('⏰ Timestamp: ' + timestamp);
    
    try {
      Logger.log('📄 Creating HTML content for PDF...');
    
    // Create HTML content for PDF
    const htmlContent = `
      <!DOCTYPE html>
      <html dir="rtl" lang="he">
      <head>
        <meta charset="UTF-8">
        <style>
          body {
            font-family: Arial, sans-serif;
            padding: 20px;
            direction: rtl;
            margin: 0;
          }
          .header {
            text-align: center;
            background-color: #1e40af;
            color: white;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
          }
          .header h1 {
            margin: 0;
            font-size: 22px;
          }
          .header p {
            margin: 3px 0 0 0;
            font-size: 12px;
          }
          .content {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 8px;
          }
          .field {
            margin-bottom: 8px;
            padding: 6px 10px;
            background-color: white;
            border-right: 3px solid #1e40af;
            font-size: 13px;
          }
          .field-label {
            font-weight: bold;
            color: #1e40af;
            display: inline;
            margin-left: 5px;
          }
          .field-value {
            display: inline;
            color: #333;
          }
          .disclaimer {
            background-color: #fff3cd;
            border-right: 3px solid #856404;
            padding: 10px;
            margin: 10px 0;
            font-size: 11px;
            line-height: 1.4;
          }
          .signature-section {
            border-right: 3px solid #1e40af;
            padding: 10px;
            background-color: white;
            margin-top: 10px;
          }
          .signature-section img {
            max-width: 250px;
            border: 1px solid #ccc;
            padding: 3px;
            background: white;
          }
          .footer {
            text-align: center;
            margin-top: 15px;
            color: #666;
            font-size: 10px;
          }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>✓ אישור קבלת ציוד</h1>
          <p>מערכת ניהול מכשירי קשר</p>
        </div>
        
        <div class="content">
          <div class="field">
            <div class="field-label">תאריך ושעה:</div>
            <div class="field-value">${timestamp}</div>
          </div>
          
          <div class="field">
            <div class="field-label">שם מלא:</div>
            <div class="field-value">${data.fullName}</div>
          </div>
          
          <div class="field">
            <div class="field-label">מספר אישי:</div>
            <div class="field-value">${data.personalNumber}</div>
          </div>
          
          <div class="field">
            <div class="field-label">טלפון:</div>
            <div class="field-value">${data.phone}</div>
          </div>
          
          ${data.unit ? `
          <div class="field">
            <div class="field-label">מסגרת:</div>
            <div class="field-value">${data.unit}</div>
          </div>
          ` : ''}
          
          ${data.radio624 ? `
          <div class="field">
            <div class="field-label">מ.ק 624:</div>
            <div class="field-value">${data.radio624}</div>
          </div>
          ` : ''}
          
          ${data.radio91 ? `
          <div class="field">
            <div class="field-label">מ.ק 91:</div>
            <div class="field-value">${data.radio91}</div>
          </div>
          ` : ''}
          
          ${data.hasColumn ? `
          <div class="field">
            <div class="field-label">עמוד:</div>
            <div class="field-value">כן${data.columnNumber ? ' - מספר: ' + data.columnNumber : ''}</div>
          </div>
          ` : ''}
          
          ${data.amplifier ? `
          <div class="field">
            <div class="field-label">מגבר:</div>
            <div class="field-value">${data.amplifier}</div>
          </div>
          ` : ''}
          
          ${data.rigidAdapter ? `
          <div class="field">
            <div class="field-label">מתאם קשיח:</div>
            <div class="field-value">${data.rigidAdapter}</div>
          </div>
          ` : ''}
          
          ${data.longAntenna ? `
          <div class="field">
            <div class="field-label">אנטנה לונג:</div>
            <div class="field-value">${data.longAntenna}</div>
          </div>
          ` : ''}
          
          ${data.mad ? `
          <div class="field">
            <div class="field-label">מעד:</div>
            <div class="field-value">${data.mad}</div>
          </div>
          ` : ''}
          
          ${data.flexibleAdapter ? `
          <div class="field">
            <div class="field-label">מתאם גמיש:</div>
            <div class="field-value">${data.flexibleAdapter}</div>
          </div>
          ` : ''}
          
          ${data.shortAntenna ? `
          <div class="field">
            <div class="field-label">אנטנה שורט:</div>
            <div class="field-value">${data.shortAntenna}</div>
          </div>
          ` : ''}
          
          ${data.speaker ? `
          <div class="field">
            <div class="field-label">רמק:</div>
            <div class="field-value">${data.speaker}</div>
          </div>
          ` : ''}
          
          ${data.madona ? `
          <div class="field">
            <div class="field-label">מדונה:</div>
            <div class="field-value">${data.madona}</div>
          </div>
          ` : ''}
          
          ${data.apple ? `
          <div class="field">
            <div class="field-label">תפוח:</div>
            <div class="field-value">${data.apple}</div>
          </div>
          ` : ''}
          
          ${data.pear ? `
          <div class="field">
            <div class="field-label">אגס:</div>
            <div class="field-value">${data.pear}</div>
          </div>
          ` : ''}
        </div>
        
        <div class="disclaimer">
          <strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את אמצעי הלחימה והציוד המפורטים במסמך זה, וכי כל הפרטים שמסרתי נכונים ומדויקים. אני מתחייב/ת לשמור על הציוד ולהחזירו במצב תקין.
        </div>
        
        ${data.signature ? `
        <div class="signature-section">
          <div class="field-label" style="display: block; margin-bottom: 5px;">חתימה:</div>
          <img src="${data.signature}" alt="חתימה"/>
        </div>
        ` : ''}
        
        <div class="footer">
          <p>מסמך זה נוצר אוטומטית על ידי מערכת ניהול מכשירי קשר | © כל הזכויות שמורות</p>
        </div>
      </body>
      </html>
    `;
    
    Logger.log('📄 HTML content created successfully');
    Logger.log('📦 Creating PDF blob...');
    
    // Create PDF from HTML
    const blob = Utilities.newBlob(htmlContent, 'text/html', 'checkout.html');
    const pdf = blob.getAs('application/pdf');
    pdf.setName(`אישור_קבלת_ציוד_${data.personalNumber}_${new Date().getTime()}.pdf`);
    
    Logger.log('✅ PDF created successfully');
    Logger.log('📧 PDF filename: ' + pdf.getName());
    
    // Send email with PDF attachment
    const subject = `אישור קבלת ציוד - ${data.fullName}`;
    const body = `
  שלום ${data.fullName},
  
  אישור קבלת הציוד נקלט במערכת בהצלחה.
  
  פרטי האישור:
  ━━━━━━━━━━━━━━━━━━━━━━
  תאריך ושעה: ${timestamp}
  מספר אישי: ${data.personalNumber}
  ${data.unit ? `מסגרת: ${data.unit}` : ''}
  
  מצורף אישור PDF מפורט.
  
  בברכה,
  מערכת ניהול מכשירי קשר
    `;
    
    Logger.log('📨 About to send email...');
    Logger.log('To: ' + data.email);
    Logger.log('Subject: ' + subject);
    Logger.log('Body length: ' + body.length);
    Logger.log('Has attachment: ' + (pdf ? 'Yes' : 'No'));
    
    try {
      MailApp.sendEmail({
        to: data.email,
        subject: subject,
        body: body,
        attachments: [pdf]
      });
      
      Logger.log('✅ Email sent successfully to: ' + data.email);
    } catch (emailError) {
      Logger.log('❌ Failed to send email!');
      Logger.log('❌ Email error: ' + emailError.toString());
      Logger.log('❌ Email error stack: ' + emailError.stack);
      throw emailError; // Re-throw to be caught by outer try-catch
    }
    
    } catch (error) {
      Logger.log('❌ Error in generateAndSendPDF: ' + error.toString());
      Logger.log('❌ Error stack: ' + error.stack);
      throw error;
    }
  }
  
  // Test function - run this manually to test email sending
  function testSendEmail() {
    Logger.log('🧪 Starting email test...');
    const parameter = {
      personalNumber: "1234567",
      action: "checkPersonalNumber"
    };
    const e = {parameter};
    
    Logger.log('Test data: ' + JSON.stringify(e));
    Logger.log('Calling doGet...');
    
    try {
      Logger.log("Result:", doGet(e));
    } catch (error) {
      Logger.log('❌ Test failed: ' + error.toString());
    }
  }
  
  // 🔐 Force permissions - run this FIRST to grant permissions
  function forcePermissions() {
    // This function explicitly uses services that require permissions
    
    // 1. Force Gmail/Mail permission
    MailApp.getRemainingDailyQuota();
    
    // 2. Force Spreadsheet permission
    SpreadsheetApp.getActiveSpreadsheet();
    
    Logger.log('✅ Permissions requested. You should now authorize.');
  }