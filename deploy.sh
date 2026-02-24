#!/bin/bash

# ================================================================
# סקריפט Deploy ידני ל-Google Apps Script
# ================================================================
# 
# שימוש:
# ./deploy.sh [all|permissions|weapons|radio]
# 
# דוגמאות:
# ./deploy.sh all          # Deploy כל הסקריפטים
# ./deploy.sh permissions  # Deploy רק permissions
# ./deploy.sh weapons      # Deploy רק weapons
# ./deploy.sh radio        # Deploy רק radio
# ================================================================

set -e  # עצור אם יש שגיאה

# צבעים
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# פונקציות עזר
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# בדיקה אם clasp מותקן
check_clasp() {
    if ! command -v clasp &> /dev/null; then
        print_error "clasp לא מותקן!"
        echo ""
        echo "התקן עם: npm install -g @google/clasp"
        exit 1
    fi
    print_success "clasp מותקן"
}

# בדיקה אם מחובר ל-Google
check_login() {
    if [ ! -f ~/.clasprc.json ]; then
        print_error "לא מחובר ל-Google!"
        echo ""
        echo "התחבר עם: clasp login"
        exit 1
    fi
    print_success "מחובר ל-Google"
}

# Deploy Permissions Script
deploy_permissions() {
    print_info "מעלה Permissions Script..."
    
    cd appScripts
    
    # בדוק אם יש .clasp.json
    if [ ! -f .clasp-permissions.json ]; then
        print_error "קובץ .clasp-permissions.json לא נמצא!"
        print_warning "צור קובץ עם: {\"scriptId\":\"YOUR_SCRIPT_ID\"}"
        cd ..
        return 1
    fi
    
    # העתק את ה-clasp config
    cp .clasp-permissions.json .clasp.json
    
    # העתק את הקוד
    cp permissionsAppScript-clean.js Code.gs
    
    # Push
    clasp push -f
    
    # Deploy
    clasp deploy --description "Manual deploy $(date '+%Y-%m-%d %H:%M:%S')"
    
    cd ..
    print_success "Permissions Script הועלה בהצלחה!"
}

# Deploy Weapons Script
deploy_weapons() {
    print_info "מעלה Weapons Script..."
    
    cd appScripts
    
    if [ ! -f .clasp-weapons.json ]; then
        print_error "קובץ .clasp-weapons.json לא נמצא!"
        print_warning "צור קובץ עם: {\"scriptId\":\"YOUR_SCRIPT_ID\"}"
        cd ..
        return 1
    fi
    
    cp .clasp-weapons.json .clasp.json
    cp weaponAppScript-clean.js Code.gs
    
    clasp push -f
    clasp deploy --description "Manual deploy $(date '+%Y-%m-%d %H:%M:%S')"
    
    cd ..
    print_success "Weapons Script הועלה בהצלחה!"
}

# Deploy Radio Script
deploy_radio() {
    print_info "מעלה Radio Script..."
    
    cd appScripts
    
    if [ ! -f .clasp-radio.json ]; then
        print_error "קובץ .clasp-radio.json לא נמצא!"
        print_warning "צור קובץ עם: {\"scriptId\":\"YOUR_SCRIPT_ID\"}"
        cd ..
        return 1
    fi
    
    cp .clasp-radio.json .clasp.json
    cp radioAppScript-clean.js Code.gs
    
    clasp push -f
    clasp deploy --description "Manual deploy $(date '+%Y-%m-%d %H:%M:%S')"
    
    cd ..
    print_success "Radio Script הועלה בהצלחה!"
}

# Main
main() {
    echo ""
    echo "🚀 Google Apps Script Deployment Tool"
    echo "======================================"
    echo ""
    
    # בדיקות
    check_clasp
    check_login
    echo ""
    
    # בדוק איזה סקריפט לעלות
    TARGET=${1:-all}
    
    case $TARGET in
        all)
            print_info "מעלה את כל הסקריפטים..."
            echo ""
            deploy_permissions || true
            echo ""
            deploy_weapons || true
            echo ""
            deploy_radio || true
            ;;
        permissions)
            deploy_permissions
            ;;
        weapons)
            deploy_weapons
            ;;
        radio)
            deploy_radio
            ;;
        *)
            print_error "אופציה לא ידועה: $TARGET"
            echo ""
            echo "שימוש: ./deploy.sh [all|permissions|weapons|radio]"
            exit 1
            ;;
    esac
    
    echo ""
    print_success "🎉 Deployment הושלם!"
    echo ""
}

# הרץ
main "$@"
