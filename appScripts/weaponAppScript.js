/**
 * Google Apps Script for Armory Checkout System
 * 
 * הוראות התקנה:
 * 1. פתח Google Sheets חדש
 * 2. לחץ על Extensions > Apps Script
 * 3. מחק את הקוד הקיים והדבק את הקוד הזה
 * 4. לחץ על Deploy > New deployment
 * 5. בחר "Web app"
 * 6. Execute as: Me
 * 7. Who has access: Anyone
 * 8. לחץ Deploy
 * 9. העתק את ה-URL שתקבל והדבק ב-HTML במשתנה GOOGLE_SCRIPT_URL
 * 
 * מסגרות: פלוגה א׳, פלוגה ב׳, פלוגה ג׳, מפקדה, ניוד, מחסר, מפג״ד
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
          if (data[i][2] == personalNumber) { // Column C is index 2 (מספר אישי)
            Logger.log('✓ Found existing record at row ' + (i + 1));
            
            // Return the existing data
            const result = JSON.stringify({
              exists: true,
              data: {
                personalNumber: data[i][2],
                fullName: data[i][1],
                phone: "0" + data[i][3],
                email: data[i][4],
                unit: data[i][5],
                weaponType: data[i][6],
                weaponNumber: data[i][7],
                trig: data[i][8],
                lior: data[i][9],
                pagion: data[i][10],
                zavon: data[i][11],
                m5: data[i][12],
                shacha: data[i][13],
                achbar: data[i][14],
                adi: data[i][15],
                ido: data[i][16],
                kiro: data[i][17],
                binoculars: data[i][18]==1?true:false,
                compass: data[i][19]==1?true:false,
                zayin: data[i][20],
                pak: data[i][21]
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
          "תאריך ושעה",
          "שם מלא", 
          "מספר אישי",
          "טלפון",
          "מייל",
          "מסגרת",
          "סוג נשק",
          "מספר נשק",
          "טריג׳",
          "ליאור",
          "פגיון",
          "זאבון",
          "m5",
          'שח"ע',
          "עכבר",
          "עדי",
          "עידו",
          "קירו",
          "משקפה",
          "מצפן",
          "ציין",
          "פק"
        ]);
        
        // Format header row
        const headerRange = sheet.getRange(1, 1, 1, 22);
        headerRange.setBackground("#2F5233");
        headerRange.setFontColor("#FFFFFF");
        headerRange.setFontWeight("bold");
        headerRange.setHorizontalAlignment("right");
      }
      
      // Check if personal number already exists in this sheet
      const personalNumberCol = 3; // Column C (מספר אישי)
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
      
      // Prepare row data - merge regular and additional sights into same columns
      const rowData = [
        formattedTimestamp,
        data.fullName,
        data.personalNumber,
        data.phone,
        data.email,
        data.unit || "",
        data.weaponType || "",
        data.weaponNumber || "",
        // Sight columns - check both regular and additional sight for each type
        (data.sightType === "טריג׳" ? data.sightNumber : "") || (data.additionalSightType === "טריג׳" ? data.additionalSightNumber : "") || "",
        (data.sightType === "ליאור" ? data.sightNumber : "") || (data.additionalSightType === "ליאור" ? data.additionalSightNumber : "") || "",
        (data.sightType === "פגיון" ? data.sightNumber : "") || (data.additionalSightType === "פגיון" ? data.additionalSightNumber : "") || "",
        (data.sightType === "זאבון" ? data.sightNumber : "") || (data.additionalSightType === "זאבון" ? data.additionalSightNumber : "") || "",
        (data.sightType === "m5" ? data.sightNumber : "") || (data.additionalSightType === "m5" ? data.additionalSightNumber : "") || "",
        // NVD columns - put number in the matching type column
        data.nvdType === 'שח"ע' ? (data.nvdNumber || "") : "",
        data.nvdType === "עכבר" ? (data.nvdNumber || "") : "",
        data.nvdType === "עדי" ? (data.nvdNumber || "") : "",
        data.nvdType === "עידו" ? (data.nvdNumber || "") : "",
        data.nvdType === "קירו" ? (data.nvdNumber || "") : "",
        // Checkboxes - use 1 instead of ✓
        data.hasBinoculars ? "1" : "",
        data.hasCompass ? "1" : "",
        // Zayin and Pak - just the number (empty if not checked)
        data.hasZayin ? (data.zayinNumber || "") : "",
        data.hasPak ? (data.pakNumber || "") : ""
      ];
      
      if (existingRow) {
        // Update existing row
        sheet.getRange(existingRow, 1, 1, 22).setValues([rowData]);
      } else {
        // Add new row
        sheet.appendRow(rowData);
      }
      
      // Also handle "כל הרשומות" sheet
      let allRecordsSheet = ss.getSheetByName("כל הרשומות");
      if (!allRecordsSheet) {
        allRecordsSheet = ss.insertSheet("כל הרשומות");
        // Add headers (WITHOUT email) - one column per sight type (combines regular and additional)
        allRecordsSheet.appendRow([
          "תאריך ושעה",
          "שם מלא",
          "מספר אישי",
          "טלפון",
          "מייל",
          "מסגרת",
          "סוג נשק",
          "מספר נשק",
          "טריג׳",
          "ליאור",
          "פגיון",
          "זאבון",
          "m5",
          'שח"ע',
          "עכבר",
          "עדי",
          "עידו",
          "קירו",
          "משקפה",
          "מצפן",
          "ציין",
          "פק"
        ]);
        
        // Format header row
        const headerRange = allRecordsSheet.getRange(1, 1, 1, 22);
        headerRange.setBackground("#2F5233");
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
        allRecordsSheet.getRange(existingRowInAll, 1, 1, 22).setValues([rowData]);
      } else {
        // Add new row to "כל הרשומות"
        allRecordsSheet.appendRow(rowData);
      }
      
      // Auto-resize columns for better readability
      sheet.autoResizeColumns(1, 22);
      allRecordsSheet.autoResizeColumns(1, 22);
      
      Logger.log('✅ Data saved to sheets successfully');
      
      // Generate PDF and send email if email is provided
      if (data.email && data.email.trim() !== "") {
        Logger.log('✉️ Attempting to send PDF to: ' + data.email);
        try {
          generateAndSendPDF(data, formattedTimestamp);
          Logger.log('✅ PDF sent successfully!');
        } catch (pdfError) {
          Logger.log('❌ PDF Error: ' + pdfError.toString());
          // Continue even if PDF fails
        }
      } else {
        Logger.log('⚠️ No email provided - skipping PDF generation');
      }
      
      // Return success response with update info
      return ContentService.createTextOutput(JSON.stringify({
        'result': 'success',
        'action': existingRow ? 'updated' : 'created',
        'row': existingRow || sheet.getLastRow(),
        'pdfSent': (data.email && data.email.trim() !== "") ? true : false
      })).setMimeType(ContentService.MimeType.JSON);
      
    } catch (error) {
      // Return error response
      return ContentService.createTextOutput(JSON.stringify({
        'result': 'error',
        'error': error.toString()
      })).setMimeType(ContentService.MimeType.JSON);
    }
  }
  
  function generateAndSendPDF(data, timestamp) {
    Logger.log('🎯 generateAndSendPDF started');
    Logger.log('Recipient email: ' + data.email);
    
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
            background-color: #2F5233;
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
            border-right: 3px solid #2F5233;
            font-size: 13px;
          }
          .field-label {
            font-weight: bold;
            color: #2F5233;
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
            border-right: 3px solid #2F5233;
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
          <h1>✓ אישור חתימה על נשק</h1>
          <p>מערכת דוח צלם מקוון</p>
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
          
          ${data.weaponType ? `
          <div class="field">
            <div class="field-label">סוג נשק:</div>
            <div class="field-value">${data.weaponType}</div>
          </div>
          ` : ''}
          
          ${data.weaponNumber ? `
          <div class="field">
            <div class="field-label">מספר נשק:</div>
            <div class="field-value">${data.weaponNumber}</div>
          </div>
          ` : ''}
          
          ${data.sightType ? `
          <div class="field">
            <div class="field-label">סוג כוונת:</div>
            <div class="field-value">${data.sightType}</div>
          </div>
          ` : ''}
          
          ${data.sightNumber ? `
          <div class="field">
            <div class="field-label">מספר כוונת:</div>
            <div class="field-value">${data.sightNumber}</div>
          </div>
          ` : ''}
          
          ${data.additionalSightType ? `
          <div class="field">
            <div class="field-label">סוג כוונת נוסף:</div>
            <div class="field-value">${data.additionalSightType}</div>
          </div>
          ` : ''}
          
          ${data.additionalSightNumber ? `
          <div class="field">
            <div class="field-label">מספר כוונת נוסף:</div>
            <div class="field-value">${data.additionalSightNumber}</div>
          </div>
          ` : ''}
          
          ${data.nvdType ? `
          <div class="field">
            <div class="field-label">סוג אמרל:</div>
            <div class="field-value">${data.nvdType}</div>
          </div>
          ` : ''}
          
          ${data.nvdNumber ? `
          <div class="field">
            <div class="field-label">מספר אמרל:</div>
            <div class="field-value">${data.nvdNumber}</div>
          </div>
          ` : ''}
          
          ${data.hasBinoculars ? `
          <div class="field">
            <div class="field-label">משקפה:</div>
            <div class="field-value">כן</div>
          </div>
          ` : ''}
          
          ${data.hasCompass ? `
          <div class="field">
            <div class="field-label">מצפן:</div>
            <div class="field-value">כן</div>
          </div>
          ` : ''}
          
          ${data.hasZayin ? `
          <div class="field">
            <div class="field-label">ציין:</div>
            <div class="field-value">כן${data.zayinNumber ? ' - מספר: ' + data.zayinNumber : ''}</div>
          </div>
          ` : ''}
          
          ${data.hasPak ? `
          <div class="field">
            <div class="field-label">פק:</div>
            <div class="field-value">כן${data.pakNumber ? ' - מספר: ' + data.pakNumber : ''}</div>
          </div>
          ` : ''}
        </div>
        
        <div class="disclaimer">
          <strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את אמצעי הלחימה והציוד המפורטים במסמך זה, וכי כל הפרטים שמסרתי נכונים ומדויקים. אני מתחייב/ת לשמור על הציוד ולהחזירו במצב תקין.
        </div>
        
        ${data.signature ? `
        <div class="signature-section">
          <div class="field-label" style="display: block; margin-bottom: 5px;">חתימת החייל:</div>
          <img src="${data.signature}" alt="חתימה"/>
        </div>
        ` : ''}
        
        <div class="footer">
          <p>מסמך זה נוצר אוטומטית על ידי מערכת דוח צלם מקוון | © כל הזכויות שמורות</p>
        </div>
      </body>
      </html>
    `;
    
    // Create PDF from HTML
    const blob = Utilities.newBlob(htmlContent, 'text/html', 'checkout.html');
    const pdf = blob.getAs('application/pdf');
    pdf.setName(`אישור_חתימה_${data.personalNumber}_${new Date().getTime()}.pdf`);
    
    // Send email with PDF attachment
    const subject = `אישור חתימה על נשק - ${data.fullName}`;
    const body = `
  שלום ${data.fullName},
  
  אישור חתימתך על נשק ואמצעי לחימה נקלט במערכת בהצלחה.
  
  פרטי החתימה:
  ━━━━━━━━━━━━━━━━━━━━━━
  תאריך ושעה: ${timestamp}
  מספר אישי: ${data.personalNumber}
  ${data.unit ? `מסגרת: ${data.unit}` : ''}
  ${data.weaponType ? `סוג נשק: ${data.weaponType}` : ''}
  ${data.weaponNumber ? `מספר נשק: ${data.weaponNumber}` : ''}
  
  מצורף אישור PDF מפורט.
  
  בברכה,
  מערכת דוח צלם מקוון
    `;
    
    Logger.log('📨 About to send email...');
    Logger.log('Email to: ' + data.email);
    Logger.log('Subject: אישור חתימה על נשק - ' + data.fullName);
    
    MailApp.sendEmail({
      to: data.email,
      subject: subject,
      body: body,
      attachments: [pdf]
    });
    
    Logger.log('✅ Email sent successfully to: ' + data.email);
  }
  
  /* For testing purposes
  function doGet(e) {
    return ContentService.createTextOutput("Google Apps Script is running. Use POST requests to submit data.");
  }*/
  
  // Test function - run this manually to test email sending
  function testSendEmail() {
    Logger.log('🧪 Starting email test...');
    const parameter = {
      personalNumber: "6153034",
      action :"checkPersonalNumber"
    };
    const e = {parameter};
    const timestamp = Utilities.formatDate(new Date(), "Asia/Jerusalem", "yyyy-MM-dd HH:mm:ss");
    
    Logger.log('Test data: ' + JSON.stringify(e));
    Logger.log('Calling generateAndSendPDF...');
    
    try {
     
      Logger.log("dddd", doGet(e));
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