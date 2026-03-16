/**
 * ================================================================
 * Email Relay Script — GAS
 * ================================================================
 * הוראות:
 *  1. צור פרויקט GAS חדש בכל חשבון Gmail (script.google.com → New project)
 *  2. מחק את הקוד הקיים והדבק את כל הקובץ הזה
 *  3. Deploy → New deployment → Web app
 *     Execute as: Me   |   Who has access: Anyone
 *  4. העתק את ה-URL ושים אותו ב-.env תחת RELAY_URL_2 / RELAY_URL_3 / ...
 *  5. חזור על כן לכל אחד מ-4 החשבונות הנוספים
 * ================================================================
 */

function doPost(e) {
  try {
    var data = JSON.parse(e.postData.contents);

    var opts = {
      to:      data.to,
      subject: data.subject,
      body:    data.body || ' '
    };

    if (data.htmlBody) {
      opts.htmlBody = data.htmlBody;
    }

    if (data.attachmentBase64 && data.attachmentName) {
      var bytes = Utilities.base64Decode(data.attachmentBase64);
      var blob  = Utilities.newBlob(bytes, data.attachmentMime || 'application/pdf', data.attachmentName);
      opts.attachments = [blob];
    }

    MailApp.sendEmail(opts);

    return ContentService
      .createTextOutput(JSON.stringify({ success: true }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    return ContentService
      .createTextOutput(JSON.stringify({ success: false, error: err.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * בדיקה: שלח ל-doPost מבדיקה ידנית
 * הרץ מה-IDE ב-Apps Script ← Run ← testRelay
 */
function testRelay() {
  var fakeEvent = {
    postData: {
      contents: JSON.stringify({
        to:      Session.getActiveUser().getEmail(),
        subject: 'Relay test',
        body:    'This relay script is working!'
      })
    }
  };
  var result = doPost(fakeEvent);
  Logger.log(result.getContent());
}
