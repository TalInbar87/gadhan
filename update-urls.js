#!/usr/bin/env node

/**
 * ================================================================
 * URL Updater for Google Apps Script Deployment
 * ================================================================
 * 
 * This script automatically updates all Google Apps Script URLs
 * in HTML files after deploying new versions.
 * 
 * Usage:
 * node update-urls.js
 * 
 * Or with specific URLs:
 * node update-urls.js --permissions=<URL> --weapons=<URL> --radio=<URL>
 * ================================================================
 */

const fs = require('fs');
const path = require('path');

// ================================================================
// CONFIGURATION
// ================================================================

const CONFIG = {
    // HTML files to update
    HTML_FILES: [
        'index.html',
        'index-secure.html',
        'weapons-checkout-secure.html',
        'radio-checkout-secure.html',
        'user-management.html',
        'audit-log.html'
    ],
    
    // Old URLs (to be replaced)
    OLD_URLS: {
        PERMISSIONS: 'https://script.google.com/macros/s/AKfycbwsFyStcK6uhjqwhENW15dCzg1L4CpsDnJ8QQ4nBm7ZZTre0k53BPrmx7AE8F2Cs_CGIQ/exec',
        WEAPONS: 'https://script.google.com/macros/s/AKfycby_vOgDCI8ZHR3sH42fMkXpDuCljYrpgZ3SO7YgnC97Yg0Rsm3y0P_uj0VNpnYo12Xg/exec',
        RADIO: 'https://script.google.com/macros/s/AKfycbxG1ymau8BHFFzIyqPqqe-jSIEZgc00SHoV4LMANhQbBRDm45U0RK1Ajh6m0Xcn099X/exec'
    },
    
    // New URLs (will be provided or prompted)
    NEW_URLS: {
        PERMISSIONS: null,
        WEAPONS: null,
        RADIO: null
    }
};

// ================================================================
// UTILITY FUNCTIONS
// ================================================================

function parseArgs() {
    const args = process.argv.slice(2);
    const parsed = {};
    
    args.forEach(arg => {
        if (arg.startsWith('--')) {
            const [key, value] = arg.substring(2).split('=');
            parsed[key.toUpperCase()] = value;
        }
    });
    
    return parsed;
}

function promptForUrl(scriptName) {
    const readline = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    return new Promise((resolve) => {
        readline.question(`הזן את ה-URL החדש עבור ${scriptName}: `, (url) => {
            readline.close();
            resolve(url.trim());
        });
    });
}

function validateUrl(url) {
    return url && url.startsWith('https://script.google.com/macros/s/') && url.endsWith('/exec');
}

function updateFileUrls(filePath, urlMappings) {
    console.log(`📝 מעדכן ${filePath}...`);
    
    let content = fs.readFileSync(filePath, 'utf8');
    let changesMade = 0;
    
    Object.entries(urlMappings).forEach(([oldUrl, newUrl]) => {
        if (!newUrl) return;
        
        const regex = new RegExp(oldUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
        const matches = content.match(regex);
        
        if (matches) {
            content = content.replace(regex, newUrl);
            changesMade += matches.length;
            console.log(`  ✓ החלפתי ${matches.length} מופעים`);
        }
    });
    
    if (changesMade > 0) {
        fs.writeFileSync(filePath, content, 'utf8');
        console.log(`✅ ${filePath} עודכן בהצלחה (${changesMade} שינויים)`);
    } else {
        console.log(`⚠️  לא נמצאו URLs לעדכון ב-${filePath}`);
    }
    
    return changesMade;
}

// ================================================================
// MAIN FUNCTION
// ================================================================

async function main() {
    console.log('');
    console.log('════════════════════════════════════════════════');
    console.log('   🔄 מעדכן URLs של Google Apps Script');
    console.log('════════════════════════════════════════════════');
    console.log('');
    
    // Parse command line arguments
    const args = parseArgs();
    
    // Get new URLs from args or prompt
    if (args.PERMISSIONS && validateUrl(args.PERMISSIONS)) {
        CONFIG.NEW_URLS.PERMISSIONS = args.PERMISSIONS;
    }
    if (args.WEAPONS && validateUrl(args.WEAPONS)) {
        CONFIG.NEW_URLS.WEAPONS = args.WEAPONS;
    }
    if (args.RADIO && validateUrl(args.RADIO)) {
        CONFIG.NEW_URLS.RADIO = args.RADIO;
    }
    
    // Prepare URL mappings
    const urlMappings = {};
    
    if (CONFIG.NEW_URLS.PERMISSIONS) {
        urlMappings[CONFIG.OLD_URLS.PERMISSIONS] = CONFIG.NEW_URLS.PERMISSIONS;
    }
    if (CONFIG.NEW_URLS.WEAPONS) {
        urlMappings[CONFIG.OLD_URLS.WEAPONS] = CONFIG.NEW_URLS.WEAPONS;
    }
    if (CONFIG.NEW_URLS.RADIO) {
        urlMappings[CONFIG.OLD_URLS.RADIO] = CONFIG.NEW_URLS.RADIO;
    }
    
    if (Object.keys(urlMappings).length === 0) {
        console.log('❌ לא סופקו URLs חדשים!');
        console.log('');
        console.log('שימוש:');
        console.log('  node update-urls.js --permissions=<URL> --weapons=<URL> --radio=<URL>');
        console.log('');
        console.log('דוגמה:');
        console.log('  node update-urls.js --permissions=https://script.google.com/macros/s/AKfyc.../exec');
        console.log('');
        process.exit(1);
    }
    
    // Show what will be updated
    console.log('📋 URLs שיעודכנו:');
    console.log('');
    Object.entries(urlMappings).forEach(([oldUrl, newUrl]) => {
        const scriptName = Object.entries(CONFIG.OLD_URLS).find(([_, url]) => url === oldUrl)?.[0];
        console.log(`${scriptName}:`);
        console.log(`  ישן: ${oldUrl}`);
        console.log(`  חדש: ${newUrl}`);
        console.log('');
    });
    
    // Update all HTML files
    let totalChanges = 0;
    
    console.log('📂 מעדכן קבצי HTML...');
    console.log('');
    
    CONFIG.HTML_FILES.forEach(filename => {
        const filePath = path.join(process.cwd(), filename);
        
        if (!fs.existsSync(filePath)) {
            console.log(`⚠️  ${filename} לא נמצא - מדלג`);
            return;
        }
        
        const changes = updateFileUrls(filePath, urlMappings);
        totalChanges += changes;
        console.log('');
    });
    
    // Summary
    console.log('════════════════════════════════════════════════');
    console.log(`✅ סיימתי! עדכנתי ${totalChanges} URLs בסך הכל`);
    console.log('════════════════════════════════════════════════');
    console.log('');
    
    if (totalChanges > 0) {
        console.log('📌 הצעד הבא:');
        console.log('   1. בדוק את הקבצים שעודכנו');
        console.log('   2. Commit ו-Push ל-GitHub');
        console.log('   3. Deploy ל-Vercel/Production');
        console.log('');
    }
}

// ================================================================
// RUN
// ================================================================

main().catch(error => {
    console.error('❌ שגיאה:', error.message);
    process.exit(1);
});
