#!/bin/bash
# ================================================================
# init.sh — Interactive Setup Wizard
# Guides the user step by step through system configuration
# ================================================================
# Requirements:
#   Mac/Linux  — Run directly: bash init.sh
#   Windows    — Install Git for Windows then run in Git Bash:
#                https://git-scm.com/download/win
#                Right-click the folder → "Git Bash Here" → bash init.sh
# ================================================================

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_JS="$REPO_DIR/appScripts/unified/Config.js"
CLASP_JSON="$REPO_DIR/appScripts/unified/.clasp.json"
ENV_FILE="$REPO_DIR/.env"

# ────────────────────────────────────────────────
# Colors
# ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ────────────────────────────────────────────────
# Helper functions
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
  echo -e "${BOLD}${YELLOW}  Step $1: $2${NC}"
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
  echo -ne "${BOLD}  ❓ $1 [yes/no]: ${NC}"
  read -r choice
  case "$choice" in
    yes|y|Y) return 0 ;;
    *) return 1 ;;
  esac
}

# ────────────────────────────────────────────────
# Welcome
# ────────────────────────────────────────────────
clear
print_header "Welcome — Equipment Management System Setup"
echo -e "  This script will guide you through setting up the system."
echo -e "  When done, you will have a fully working instance."
echo ""
echo -e "  ${BOLD}What we will do:${NC}"
echo -e "    1️⃣  Check required tools"
echo -e "    2️⃣  Sign in to Google (clasp)"
echo -e "    3️⃣  Connect Google Apps Script project"
echo -e "    4️⃣  Configure Google Sheets"
echo -e "    5️⃣  Set security key (JWT)"
echo -e "    6️⃣  Upload code to Google"
echo -e "    7️⃣  Create .env file"
echo -e "    8️⃣  Configure Hosting"
echo ""
echo -e "  ${YELLOW}⏱️  Estimated time: ~10-15 minutes${NC}"
echo ""
# Windows detection
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
  echo -e "  ${YELLOW}💻 Windows detected — you are running in Git Bash. Great!${NC}"
fi
echo ""

if ! confirm "Are you ready to begin?"; then
  echo ""
  echo -e "  ${YELLOW}Exiting. Run ./init.sh again when you're ready.${NC}"
  exit 0
fi

# ════════════════════════════════════════════════
# Step 0: Check prerequisites
# ════════════════════════════════════════════════
print_step "0" "Checking required tools"

# git
if command -v git &>/dev/null; then
  print_success "git is installed ($(git --version | head -1))"
else
  print_error "git is not installed. Install it from: https://git-scm.com"
  exit 1
fi

# node
if command -v node &>/dev/null; then
  print_success "Node.js is installed ($(node --version))"
else
  print_error "Node.js is not installed. Install it from: https://nodejs.org"
  exit 1
fi

# python3
if command -v python3 &>/dev/null; then
  print_success "Python3 is installed ($(python3 --version))"
else
  print_error "Python3 is not installed. Install it from: https://www.python.org/downloads"
  if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    print_info "Windows: download Python from https://python.org ⚠️ check 'Add Python to PATH'"
  fi
  exit 1
fi

# clasp
if command -v clasp &>/dev/null; then
  print_success "clasp is installed ($(clasp --version 2>/dev/null || echo 'unknown version'))"
else
  print_warning "clasp is not installed. Installing..."
  npm install -g @google/clasp
  print_success "clasp installed successfully!"
fi

# openssl (for JWT secret generation)
if command -v openssl &>/dev/null; then
  print_success "openssl is available"
else
  print_warning "openssl not found — security key will be generated manually"
fi

# ════════════════════════════════════════════════
# Step 1: clasp login
# ════════════════════════════════════════════════
print_step "1" "Sign in to Google"

echo -e "  A browser window will open for Google authentication."
echo -e "  Sign in with the account where you want to host the project."
echo ""

if confirm "Are you already signed in to clasp with this account?"; then
  print_success "Skipping sign-in"
else
  clasp login
  print_success "Signed in successfully!"
fi

# ════════════════════════════════════════════════
# Step 2: Connect GAS project
# ════════════════════════════════════════════════
print_step "2" "Connect Google Apps Script project"

echo -e "  You have two options:"
echo -e "    ${BOLD}1)${NC} Create a new GAS project (recommended)"
echo -e "    ${BOLD}2)${NC} Use an existing GAS project"
echo ""
echo -ne "  ${BOLD}Choose 1 or 2: ${NC}"
read -r GAS_CHOICE

if [ "$GAS_CHOICE" = "1" ]; then
  echo ""
  print_info "Creating new GAS project..."
  cd "$REPO_DIR/appScripts/unified"
  CREATE_OUTPUT=$(clasp create --type webapp --title "Equipment Management System" --rootDir . 2>&1)
  echo "$CREATE_OUTPUT"
  SCRIPT_ID=$(echo "$CREATE_OUTPUT" | grep -oE '[a-zA-Z0-9_-]{57}' | head -1)
  if [ -z "$SCRIPT_ID" ]; then
    print_warning "Could not extract scriptId automatically."
    print_info "Go to: https://script.google.com → your new project → Settings (⚙️) → Script ID"
    SCRIPT_ID=$(ask "Paste the Script ID:")
  fi
else
  echo ""
  print_info "Go to: https://script.google.com → your project → Settings (⚙️) → Script ID"
  SCRIPT_ID=$(ask "Paste your Script ID:")
fi

# Update .clasp.json
cat > "$CLASP_JSON" <<EOF
{"scriptId": "$SCRIPT_ID", "rootDir": "."}
EOF
print_success "Script ID set: $SCRIPT_ID"

# ════════════════════════════════════════════════
# Step 3: Google Sheets
# ════════════════════════════════════════════════
print_step "3" "Configure Google Sheets"

echo -e "  The system requires 7 separate Google Sheets."
echo -e "  Create them now at: ${BOLD}https://sheets.google.com${NC}"
echo ""
echo -e "  ${BOLD}Required sheets:${NC}"
echo -e "    1️⃣  ${BOLD}Users${NC}        — user accounts and passwords"
echo -e "    2️⃣  ${BOLD}Audit Log${NC}    — record of all system actions"
echo -e "    3️⃣  ${BOLD}Weapons${NC}      — weapons and equipment table"
echo -e "    4️⃣  ${BOLD}Radio${NC}        — communications equipment table"
echo -e "    5️⃣  ${BOLD}Armory${NC}       — armory inventory counts"
echo -e "    6️⃣  ${BOLD}Bunker${NC}       — bunker inventory and dispensing"
echo -e "    7️⃣  ${BOLD}Apsnaut${NC}      — apsnaut equipment management"
echo ""
echo -e "  ${YELLOW}How to find a Sheet ID?${NC}"
echo -e "  In the sheet URL: docs.google.com/spreadsheets/d/${BOLD}[THIS IS THE ID]${NC}/edit"
echo ""

echo -ne "  ${BOLD}Press Enter once you have created all 7 sheets...${NC}"
read -r

echo ""
USERS_SHEET_ID=$(ask "1️⃣  Sheet ID for Users:")
AUDIT_SHEET_ID=$(ask "2️⃣  Sheet ID for Audit Log:")
WEAPONS_SHEET_ID=$(ask "3️⃣  Sheet ID for Weapons:")
RADIO_SHEET_ID=$(ask "4️⃣  Sheet ID for Radio:")
ARMORY_SHEET_ID=$(ask "5️⃣  Sheet ID for Armory:")
BUNKER_SHEET_ID=$(ask "6️⃣  Sheet ID for Bunker:")
APSNAUT_SHEET_ID=$(ask "7️⃣  Sheet ID for Apsnaut:")

echo ""
print_info "Updating Config.js with Sheet IDs..."

# Update Config.js — replace each Sheet ID line
python3 - <<PYEOF
import re

with open('$CONFIG_JS', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(r"USERS:\s*'[^']*'",     "USERS:     '$USERS_SHEET_ID'",   content)
content = re.sub(r"AUDIT_LOG:\s*'[^']*'", "AUDIT_LOG: '$AUDIT_SHEET_ID'",   content)
content = re.sub(r"WEAPONS:\s*'[^']*'",   "WEAPONS:   '$WEAPONS_SHEET_ID'", content)
content = re.sub(r"RADIO:\s*'[^']*'",     "RADIO:     '$RADIO_SHEET_ID'",   content)
content = re.sub(r"ARMORY:\s*'[^']*'",    "ARMORY:    '$ARMORY_SHEET_ID'",  content)
content = re.sub(r"BUNKER:\s*'[^']*'",    "BUNKER:    '$BUNKER_SHEET_ID'",  content)
content = re.sub(r"APSNAUT:\s*'[^']*'",   "APSNAUT:   '$APSNAUT_SHEET_ID'", content)

with open('$CONFIG_JS', 'w', encoding='utf-8') as f:
    f.write(content)

print("Sheet IDs updated successfully")
PYEOF

print_success "Sheet IDs updated in Config.js"

# ════════════════════════════════════════════════
# Step 4: JWT Security Key
# ════════════════════════════════════════════════
print_step "4" "Set Security Key (JWT Secret)"

echo -e "  This key protects all user tokens."
echo -e "  ${YELLOW}Important: save it somewhere safe — if it changes, all users will be logged out.${NC}"
echo ""

if confirm "Generate a random security key? (recommended)"; then
  if command -v openssl &>/dev/null; then
    JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n/+=' | head -c 48)
  else
    JWT_SECRET=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | head -c 48)
  fi
  echo ""
  print_info "Generated key: ${BOLD}$JWT_SECRET${NC}"
  print_warning "Save this key! You will not be able to recover it."
else
  JWT_SECRET=$(ask "Enter your own security key (minimum 32 characters):")
  if [ ${#JWT_SECRET} -lt 32 ]; then
    print_error "Key is too short. Minimum 32 characters."
    exit 1
  fi
fi

# Update JWT_SECRET in Config.js
python3 - <<PYEOF
import re

with open('$CONFIG_JS', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(r"JWT_SECRET:\s*'[^']*'", "JWT_SECRET: '$JWT_SECRET'", content)

with open('$CONFIG_JS', 'w', encoding='utf-8') as f:
    f.write(content)

print("JWT_SECRET updated successfully")
PYEOF

print_success "Security key set in Config.js"

# ════════════════════════════════════════════════
# Step 5: Upload code to Google Apps Script
# ════════════════════════════════════════════════
print_step "5" "Upload code to Google (clasp push + deploy)"

echo -e "  Uploading all GAS files to your project..."
echo ""

cd "$REPO_DIR/appScripts/unified"

clasp push --force
print_success "Code uploaded!"

echo ""
print_info "Creating new deployment..."
DEPLOY_OUTPUT=$(clasp deploy -d "init deploy $(date '+%Y-%m-%d')" 2>&1)
echo "$DEPLOY_OUTPUT"

NEW_DEPLOYMENT_ID=$(echo "$DEPLOY_OUTPUT" | grep -oE 'AKfycb[A-Za-z0-9_\-]+' | head -1)

if [ -z "$NEW_DEPLOYMENT_ID" ]; then
  echo ""
  print_warning "Could not extract Deployment ID automatically."
  print_info "Go to GAS → Deploy → Manage Deployments → copy the Deployment ID"
  NEW_DEPLOYMENT_ID=$(ask "Paste the Deployment ID (starts with AKfycb...):")
fi

NEW_URL="https://script.google.com/macros/s/$NEW_DEPLOYMENT_ID/exec"
print_success "Deployment ID: $NEW_DEPLOYMENT_ID"
print_success "URL: $NEW_URL"

echo ""
print_warning "Important: make sure the Deployment is set to 'Anyone' (not 'Anyone with Google Account')"
print_info "GAS → Deploy → Manage Deployments → ✏️ Edit → Who has access → Anyone"

# ════════════════════════════════════════════════
# Step 6: Create .env and config.js
# ════════════════════════════════════════════════
print_step "6" "Create configuration files"

cd "$REPO_DIR"

cat > "$ENV_FILE" <<EOF
GAS_DEPLOYMENT_ID=$NEW_DEPLOYMENT_ID
GAS_URL=$NEW_URL
EOF
print_success ".env created"

GAS_URL="$NEW_URL" bash "$REPO_DIR/build.sh"
print_success "config.js created"

# ════════════════════════════════════════════════
# Step 7: Configure Hosting
# ════════════════════════════════════════════════
print_step "7" "Configure Hosting"

echo -e "  Choose where to host the frontend:"
echo -e "    ${BOLD}1)${NC} Netlify (recommended — simple and free)"
echo -e "    ${BOLD}2)${NC} Vercel"
echo -e "    ${BOLD}3)${NC} Static server / other"
echo ""
echo -ne "  ${BOLD}Choose 1, 2, or 3: ${NC}"
read -r HOST_CHOICE

echo ""
case "$HOST_CHOICE" in
  1)
    echo -e "  ${BOLD}${GREEN}Netlify — Instructions:${NC}"
    echo -e "  ─────────────────────────────────────────────"
    echo -e "  1. Go to: ${BOLD}https://netlify.com${NC} → New site from Git"
    echo -e "  2. Connect your GitHub repository"
    echo -e "  3. Build settings:"
    echo -e "     Build command:   ${BOLD}bash build.sh${NC}"
    echo -e "     Publish dir:     ${BOLD}.${NC}"
    echo -e "  4. Site Settings → Environment Variables → Add:"
    echo -e "     Key:   ${BOLD}GAS_URL${NC}"
    echo -e "     Value: ${BOLD}$NEW_URL${NC}"
    echo -e "  5. Trigger Deploy → Deploy site"
    echo -e "  ─────────────────────────────────────────────"
    ;;
  2)
    echo -e "  ${BOLD}${GREEN}Vercel — Instructions:${NC}"
    echo -e "  ─────────────────────────────────────────────"
    echo -e "  1. Go to: ${BOLD}https://vercel.com${NC} → Add New Project"
    echo -e "  2. Connect your GitHub repository"
    echo -e "  3. Build settings:"
    echo -e "     Build command:   ${BOLD}bash build.sh${NC}"
    echo -e "     Output dir:      ${BOLD}.${NC}"
    echo -e "  4. Environment Variables → Add:"
    echo -e "     Name:  ${BOLD}GAS_URL${NC}"
    echo -e "     Value: ${BOLD}$NEW_URL${NC}"
    echo -e "  5. Deploy"
    echo -e "  ─────────────────────────────────────────────"
    ;;
  3)
    echo -e "  ${BOLD}${GREEN}Static server — Instructions:${NC}"
    echo -e "  ─────────────────────────────────────────────"
    echo -e "  All HTML files + auth-client.js + config.js"
    echo -e "  are ready to upload to any static server."
    echo -e ""
    echo -e "  ${BOLD}Before uploading:${NC}"
    echo -e "  1. config.js already contains the correct URL ✅"
    echo -e "  2. Upload all root files to your server"
    echo -e "  ─────────────────────────────────────────────"
    ;;
  *)
    print_warning "Unknown choice — skipping"
    ;;
esac

# ════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${BOLD}   🎉 Setup completed successfully!             ${NC}${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Summary:${NC}"
echo -e "  🔗 GAS URL:     $NEW_URL"
echo -e "  🔑 Script ID:   $SCRIPT_ID"
echo -e "  📄 .env:        created ✅"
echo -e "  📄 config.js:   created ✅"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "  1. Create the first admin user via the GAS project"
echo -e "     (in GAS editor: run the function createInitialAdmin)"
echo -e "  2. Open index.html and verify login works"
echo -e "  3. For future updates: ${BOLD}./deploy.sh${NC}"
echo ""
echo -e "  ${CYAN}Good luck! 🚀${NC}"
echo ""
