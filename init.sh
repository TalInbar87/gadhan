#!/bin/bash
# ================================================================
# init.sh — אשף התקנה אינטראקטיבי
# מדריך את המשתמש שלב אחר שלב בהגדרת המערכת
# ================================================================

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_JS="$REPO_DIR/appScripts/unified/Config.js"
CLASP_JSON="$REPO_DIR/appScripts/unified/.clasp.json"
ENV_FILE="$REPO_DIR/.env"

# ────────────────────────────────────────────────
# צבעים
# ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ────────────────────────────────────────────────
# פונקציות עזר
# ────────────────────────────────────────────────
print_header() {
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${BOLD}   $1${NC}${CYAN}$(printf '%*s' $((47 - ${#1})) '')║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
}

print_step() {
  echo ""
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${YELLOW}  שלב $1: $2${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
}

print_success() {
  echo -e "  ${GREEN}✅ $1${NC}"
}

print_info() {
  echo -e "  ${CYAN}ℹ️  $1${NC}"
}

print_warning() {
  echo -e "  ${YELLOW}⚠️  $1${NC}"
}

print_error() {
  echo -e "  ${RED}❌ $1${NC}"
}

ask() {
  echo -ne "${BOLD}  👉 $1${NC} "
  read -r REPLY
  echo "$REPLY"
}

ask_secret() {
  echo -ne "${BOLD}  🔐 $1${NC} "
  read -rs REPLY
  echo ""
  echo "$REPLY"
}

confirm() {
  echo -ne "${BOLD}  ❓ $1 [כן/לא]: ${NC}"
  read -r choice
  case "$choice" in
    כן|yes|y|Y|כ) return 0 ;;
    *) return 1 ;;
  esac
}

# ────────────────────────────────────────────────
# ברכת שלום
# ────────────────────────────────────────────────
clear
print_header "ברוך הבא — אשף הגדרת מערכת ניהול ציוד"
echo -e "  הסקריפט הזה ינחה אותך בהגדרת המערכת לשימוש שלך."
echo -e "  בסיום תהיה לך מערכת מלאה ופעילה."
echo ""
echo -e "  ${BOLD}מה נעשה:${NC}"
echo -e "    1️⃣  בדיקת כלים מותקנים"
echo -e "    2️⃣  כניסה לחשבון Google (clasp)"
echo -e "    3️⃣  חיבור פרויקט Google Apps Script"
echo -e "    4️⃣  הגדרת Google Sheets"
echo -e "    5️⃣  הגדרת מפתח אבטחה (JWT)"
echo -e "    6️⃣  העלאת הקוד ל-Google"
echo -e "    7️⃣  יצירת קובץ .env"
echo -e "    8️⃣  הגדרת Hosting"
echo ""
echo -e "  ${YELLOW}⏱️  זמן משוער: כ-10-15 דקות${NC}"
echo ""

if ! confirm "האם אתה מוכן להתחיל?"; then
  echo ""
  echo -e "  ${YELLOW}יציאה. הרץ ./init.sh שוב כשתהיה מוכן.${NC}"
  exit 0
fi

# ════════════════════════════════════════════════
# שלב 0: בדיקת תנאים מוקדמים
# ════════════════════════════════════════════════
print_step "0" "בדיקת כלים מותקנים"

# git
if command -v git &>/dev/null; then
  print_success "git מותקן ($(git --version | head -1))"
else
  print_error "git לא מותקן. התקן אותו מ: https://git-scm.com"
  exit 1
fi

# node
if command -v node &>/dev/null; then
  print_success "Node.js מותקן ($(node --version))"
else
  print_error "Node.js לא מותקן. התקן אותו מ: https://nodejs.org"
  exit 1
fi

# clasp
if command -v clasp &>/dev/null; then
  print_success "clasp מותקן ($(clasp --version 2>/dev/null || echo 'גרסה לא ידועה'))"
else
  print_warning "clasp לא מותקן. מתקין..."
  npm install -g @google/clasp
  print_success "clasp הותקן בהצלחה!"
fi

# openssl (ליצירת JWT secret)
if command -v openssl &>/dev/null; then
  print_success "openssl זמין"
else
  print_warning "openssl לא נמצא — יווצר מפתח אבטחה ידנית"
fi

# ════════════════════════════════════════════════
# שלב 1: clasp login
# ════════════════════════════════════════════════
print_step "1" "כניסה לחשבון Google"

echo -e "  נפתח חלון דפדפן לאימות Google."
echo -e "  היכנס עם החשבון שבו רוצה לאחסן את הפרויקט."
echo ""

if confirm "האם כבר מחובר ל-clasp מחשבון זה?"; then
  print_success "דילוג על כניסה"
else
  clasp login
  print_success "כניסה בוצעה!"
fi

# ════════════════════════════════════════════════
# שלב 2: חיבור פרויקט GAS
# ════════════════════════════════════════════════
print_step "2" "חיבור פרויקט Google Apps Script"

echo -e "  יש לך שתי אפשרויות:"
echo -e "    ${BOLD}1)${NC} צור פרויקט GAS חדש (מומלץ)"
echo -e "    ${BOLD}2)${NC} השתמש בפרויקט GAS קיים"
echo ""
echo -ne "  ${BOLD}בחר 1 או 2: ${NC}"
read -r GAS_CHOICE

if [ "$GAS_CHOICE" = "1" ]; then
  echo ""
  print_info "יוצר פרויקט GAS חדש..."
  cd "$REPO_DIR/appScripts/unified"
  CREATE_OUTPUT=$(clasp create --type webapp --title "מערכת ניהול ציוד" --rootDir . 2>&1)
  echo "$CREATE_OUTPUT"
  SCRIPT_ID=$(echo "$CREATE_OUTPUT" | grep -oE '[a-zA-Z0-9_-]{57}' | head -1)
  if [ -z "$SCRIPT_ID" ]; then
    print_warning "לא הצלחנו לחלץ scriptId אוטומטית."
    print_info "כנס ל: https://script.google.com → הפרויקט החדש → הגדרות (⚙️) → Script ID"
    SCRIPT_ID=$(ask "הדבק את ה-Script ID:")
  fi
else
  echo ""
  print_info "כנס ל: https://script.google.com → הפרויקט שלך → הגדרות (⚙️) → Script ID"
  SCRIPT_ID=$(ask "הדבק את ה-Script ID שלך:")
fi

# עדכן .clasp.json
cat > "$CLASP_JSON" <<EOF
{"scriptId": "$SCRIPT_ID", "rootDir": "."}
EOF
print_success "Script ID הוגדר: $SCRIPT_ID"

# ════════════════════════════════════════════════
# שלב 3: Google Sheets
# ════════════════════════════════════════════════
print_step "3" "הגדרת Google Sheets"

echo -e "  המערכת זקוקה ל-4 גיליונות Google Sheets נפרדים."
echo -e "  צור אותם עכשיו ב: ${BOLD}https://sheets.google.com${NC}"
echo ""
echo -e "  ${BOLD}הגיליונות הנדרשים:${NC}"
echo -e "    1️⃣  ${BOLD}משתמשים${NC} — רשימת המשתמשים והסיסמאות"
echo -e "    2️⃣  ${BOLD}יומן ביקורת${NC} — תיעוד כל הפעולות במערכת"
echo -e "    3️⃣  ${BOLD}נשק${NC} — טבלת הנשקים והציוד"
echo -e "    4️⃣  ${BOLD}קשר${NC} — טבלת ציוד הקשר"
echo ""
echo -e "  ${YELLOW}איך למצוא Sheet ID?${NC}"
echo -e "  בכתובת הגיליון: docs.google.com/spreadsheets/d/${BOLD}[זה ה-ID]${NC}/edit"
echo ""

echo -ne "  ${BOLD}לחץ Enter כשיצרת את 4 הגיליונות...${NC}"
read -r

echo ""
USERS_SHEET_ID=$(ask "1️⃣  Sheet ID של גיליון משתמשים:")
AUDIT_SHEET_ID=$(ask "2️⃣  Sheet ID של יומן ביקורת:")
WEAPONS_SHEET_ID=$(ask "3️⃣  Sheet ID של נשק:")
RADIO_SHEET_ID=$(ask "4️⃣  Sheet ID של קשר:")

echo ""
print_info "מעדכן Config.js עם ה-Sheet IDs..."

# עדכן Config.js — מחליף כל שורת Sheet ID
python3 - <<PYEOF
import re

with open('$CONFIG_JS', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(r"USERS:\s*'[^']*'", "USERS:     '$USERS_SHEET_ID'", content)
content = re.sub(r"AUDIT_LOG:\s*'[^']*'", "AUDIT_LOG: '$AUDIT_SHEET_ID'", content)
content = re.sub(r"WEAPONS:\s*'[^']*'", "WEAPONS:   '$WEAPONS_SHEET_ID'", content)
content = re.sub(r"RADIO:\s*'[^']*'", "RADIO:     '$RADIO_SHEET_ID'", content)

with open('$CONFIG_JS', 'w', encoding='utf-8') as f:
    f.write(content)

print("Sheet IDs updated successfully")
PYEOF

print_success "Sheet IDs עודכנו ב-Config.js"

# ════════════════════════════════════════════════
# שלב 4: מפתח אבטחה JWT
# ════════════════════════════════════════════════
print_step "4" "הגדרת מפתח אבטחה (JWT Secret)"

echo -e "  המפתח הזה מגן על כל הטוקנים של המשתמשים."
echo -e "  ${YELLOW}חשוב: שמור אותו במקום בטוח — אם ישתנה כל המשתמשים יתנתקו.${NC}"
echo ""

if confirm "האם לייצר מפתח אבטחה אקראי? (מומלץ)"; then
  if command -v openssl &>/dev/null; then
    JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n/+=' | head -c 48)
  else
    JWT_SECRET=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | head -c 48)
  fi
  echo ""
  print_info "המפתח שנוצר: ${BOLD}$JWT_SECRET${NC}"
  print_warning "שמור את המפתח הזה! לא תוכל לשחזר אותו."
else
  JWT_SECRET=$(ask "הזן מפתח אבטחה משלך (מינימום 32 תווים):")
  if [ ${#JWT_SECRET} -lt 32 ]; then
    print_error "המפתח קצר מדי. מינימום 32 תווים."
    exit 1
  fi
fi

# עדכן JWT_SECRET ב-Config.js
python3 - <<PYEOF
import re

with open('$CONFIG_JS', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(r"JWT_SECRET:\s*'[^']*'", "JWT_SECRET: '$JWT_SECRET'", content)

with open('$CONFIG_JS', 'w', encoding='utf-8') as f:
    f.write(content)

print("JWT_SECRET updated successfully")
PYEOF

print_success "מפתח אבטחה הוגדר ב-Config.js"

# ════════════════════════════════════════════════
# שלב 5: העלאת הקוד ל-Google Apps Script
# ════════════════════════════════════════════════
print_step "5" "העלאת הקוד ל-Google (clasp push + deploy)"

echo -e "  מעלה את כל קבצי ה-GAS לפרויקט שלך..."
echo ""

cd "$REPO_DIR/appScripts/unified"

clasp push --force
print_success "הקוד הועלה!"

echo ""
print_info "יוצר deployment חדש..."
DEPLOY_OUTPUT=$(clasp deploy -d "init deploy $(date '+%Y-%m-%d')" 2>&1)
echo "$DEPLOY_OUTPUT"

NEW_DEPLOYMENT_ID=$(echo "$DEPLOY_OUTPUT" | grep -oE 'AKfycb[A-Za-z0-9_\-]+' | head -1)

if [ -z "$NEW_DEPLOYMENT_ID" ]; then
  echo ""
  print_warning "לא הצלחנו לחלץ את ה-Deployment ID אוטומטית."
  print_info "כנס ל-GAS → Deploy → Manage Deployments → העתק את ה-Deployment ID"
  NEW_DEPLOYMENT_ID=$(ask "הדבק את ה-Deployment ID (מתחיל ב-AKfycb...):")
fi

NEW_URL="https://script.google.com/macros/s/$NEW_DEPLOYMENT_ID/exec"
print_success "Deployment ID: $NEW_DEPLOYMENT_ID"
print_success "URL: $NEW_URL"

echo ""
print_warning "חשוב: ודא שה-Deployment מוגדר ל-'Anyone' (ולא 'Anyone with Google Account')"
print_info "GAS → Deploy → Manage Deployments → ✏️ Edit → Who has access → Anyone"

# ════════════════════════════════════════════════
# שלב 6: יצירת .env ו-config.js
# ════════════════════════════════════════════════
print_step "6" "יצירת קבצי קונפיגורציה"

cd "$REPO_DIR"

cat > "$ENV_FILE" <<EOF
GAS_DEPLOYMENT_ID=$NEW_DEPLOYMENT_ID
GAS_URL=$NEW_URL
EOF
print_success ".env נוצר"

GAS_URL="$NEW_URL" bash "$REPO_DIR/build.sh"
print_success "config.js נוצר"

# ════════════════════════════════════════════════
# שלב 7: הגדרת Hosting
# ════════════════════════════════════════════════
print_step "7" "הגדרת Hosting"

echo -e "  בחר איפה לאחסן את הפרונטאנד:"
echo -e "    ${BOLD}1)${NC} Netlify (מומלץ — פשוט ובחינם)"
echo -e "    ${BOLD}2)${NC} Vercel"
echo -e "    ${BOLD}3)${NC} שרת סטטי / אחר"
echo ""
echo -ne "  ${BOLD}בחר 1, 2, או 3: ${NC}"
read -r HOST_CHOICE

echo ""
case "$HOST_CHOICE" in
  1)
    echo -e "  ${BOLD}${GREEN}Netlify — הוראות:${NC}"
    echo -e "  ─────────────────────────────────────────────"
    echo -e "  1. כנס ל: ${BOLD}https://netlify.com${NC} → New site from Git"
    echo -e "  2. חבר את ה-GitHub repository שלך"
    echo -e "  3. הגדרות Build:"
    echo -e "     Build command:   ${BOLD}bash build.sh${NC}"
    echo -e "     Publish dir:     ${BOLD}.${NC}"
    echo -e "  4. Site Settings → Environment Variables → Add:"
    echo -e "     Key:   ${BOLD}GAS_URL${NC}"
    echo -e "     Value: ${BOLD}$NEW_URL${NC}"
    echo -e "  5. Trigger Deploy → Deploy site"
    echo -e "  ─────────────────────────────────────────────"
    ;;
  2)
    echo -e "  ${BOLD}${GREEN}Vercel — הוראות:${NC}"
    echo -e "  ─────────────────────────────────────────────"
    echo -e "  1. כנס ל: ${BOLD}https://vercel.com${NC} → Add New Project"
    echo -e "  2. חבר את ה-GitHub repository שלך"
    echo -e "  3. הגדרות Build:"
    echo -e "     Build command:   ${BOLD}bash build.sh${NC}"
    echo -e "     Output dir:      ${BOLD}.${NC}"
    echo -e "  4. Environment Variables → Add:"
    echo -e "     Name:  ${BOLD}GAS_URL${NC}"
    echo -e "     Value: ${BOLD}$NEW_URL${NC}"
    echo -e "  5. Deploy"
    echo -e "  ─────────────────────────────────────────────"
    ;;
  3)
    echo -e "  ${BOLD}${GREEN}שרת סטטי — הוראות:${NC}"
    echo -e "  ─────────────────────────────────────────────"
    echo -e "  כל קבצי ה-HTML + auth-client.js + config.js"
    echo -e "  מוכנים להעלאה לכל שרת סטטי."
    echo -e ""
    echo -e "  ${BOLD}לפני העלאה:${NC}"
    echo -e "  1. config.js כבר מכיל את ה-URL הנכון ✅"
    echo -e "  2. העלה את כל קבצי השורש לשרת שלך"
    echo -e "  ─────────────────────────────────────────────"
    ;;
  *)
    print_warning "בחירה לא מוכרת — דלג"
    ;;
esac

# ════════════════════════════════════════════════
# סיום
# ════════════════════════════════════════════════
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${BOLD}   🎉 ההגדרה הושלמה בהצלחה!                    ${NC}${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}סיכום:${NC}"
echo -e "  🔗 GAS URL:     $NEW_URL"
echo -e "  🔑 Script ID:   $SCRIPT_ID"
echo -e "  📄 .env:        נוצר ✅"
echo -e "  📄 config.js:   נוצר ✅"
echo ""
echo -e "  ${BOLD}השלבים הבאים:${NC}"
echo -e "  1. צור משתמש admin ראשון דרך ה-GAS project"
echo -e "     (ב-GAS editor: הרץ את הפונקציה createInitialAdmin)"
echo -e "  2. גש ל-index.html ובדוק שהכניסה עובדת"
echo -e "  3. לעתיד — להפעיל שינויים: ${BOLD}./deploy.sh${NC}"
echo ""
echo -e "  ${CYAN}בהצלחה! 🚀${NC}"
echo ""
