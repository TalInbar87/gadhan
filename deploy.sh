#!/bin/bash
# ================================================================
# deploy.sh — GAS + Git auto-deploy
# ================================================================
# 1. טוען GAS_URL מקובץ .env
# 2. מייצר config.js מ-.env (URL לא נמצא ב-HTML)
# 3. בודק אם יש שינויים בקבצי GAS
# 4. אם כן — clasp push + עדכון deployment
# 5. אם ה-URL השתנה — מעדכן .env + config.js
# 6. commit & push לגיט
# ================================================================

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GAS_DIR="$REPO_DIR/appScripts/unified"
ENV_FILE="$REPO_DIR/.env"
CONFIG_JS="$REPO_DIR/config.js"
GAS_CONFIG_JS="$REPO_DIR/appScripts/unified/Config.js"

# ────────────────────────────────────────────────
# 0. טען משתנים מ-.env
# ────────────────────────────────────────────────
if [ ! -f "$ENV_FILE" ]; then
  echo "❌ .env file not found at $ENV_FILE"
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

if [ -z "$GAS_DEPLOYMENT_ID" ] || [ -z "$GAS_URL" ]; then
  echo "❌ GAS_DEPLOYMENT_ID or GAS_URL is not set in .env"
  exit 1
fi

if [ -z "$SHEET_USERS" ] || [ -z "$SHEET_AUDIT_LOG" ] || [ -z "$SHEET_WEAPONS" ] || [ -z "$SHEET_RADIO" ] || [ -z "$JWT_SECRET" ]; then
  echo "❌ Sheet IDs or JWT_SECRET are not set in .env"
  exit 1
fi

echo "📋 Using deployment: $GAS_DEPLOYMENT_ID"

# ────────────────────────────────────────────────
# 1. צור config.js מ-.env (מקור האמת)
# ────────────────────────────────────────────────
echo "⚙️  Generating config.js..."
cd "$REPO_DIR"
bash build.sh

# ────────────────────────────────────────────────
# 2. בדוק שינויים ב-GAS
# ────────────────────────────────────────────────
echo "🔍 Checking for GAS changes..."

GAS_CHANGED=false
# בדוק שינויים בקבצים מוטרקים
if ! git -C "$REPO_DIR" diff --quiet appScripts/unified/ 2>/dev/null; then
  GAS_CHANGED=true
fi
if git -C "$REPO_DIR" diff --cached --name-only | grep -q "^appScripts/unified/"; then
  GAS_CHANGED=true
fi
# בדוק שינויים ב-Config.js (gitignored) — השווה לפלייסהולדרים
if grep -q "YOUR_" "$GAS_CONFIG_JS" 2>/dev/null; then
  echo "⚠️  Config.js עדיין מכיל placeholders — הרץ init.sh תחילה"
  exit 1
fi
# Config.js תמיד נוזרק ונדחף — ייתכן שהוא שונה
GAS_CHANGED=true

if [ "$GAS_CHANGED" = false ]; then
  echo "✅ No GAS changes — skipping clasp"
else
  # ────────────────────────────────────────────────
  # 3. הזרק ערכים מ-.env ל-Config.js לפני push
  # ────────────────────────────────────────────────
  echo "⚙️  Injecting .env values into Config.js..."
  python3 - <<PYEOF
import re

with open('$GAS_CONFIG_JS', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(r"JWT_SECRET:\s*'[^']*'",   "JWT_SECRET: '$JWT_SECRET'",         content)
content = re.sub(r"USERS:\s*'[^']*'",         "USERS:     '$SHEET_USERS'",          content)
content = re.sub(r"AUDIT_LOG:\s*'[^']*'",     "AUDIT_LOG: '$SHEET_AUDIT_LOG'",      content)
content = re.sub(r"WEAPONS:\s*'[^']*'",       "WEAPONS:   '$SHEET_WEAPONS'",        content)
content = re.sub(r"RADIO:\s*'[^']*'",         "RADIO:     '$SHEET_RADIO'",          content)

with open('$GAS_CONFIG_JS', 'w', encoding='utf-8') as f:
    f.write(content)
PYEOF
  echo "  ✅ Config.js מוכן"

  # ────────────────────────────────────────────────
  # 4. clasp push + deploy
  # ────────────────────────────────────────────────
  echo "📦 Pushing GAS files..."
  cd "$GAS_DIR"
  clasp push --force

  echo "🚀 Deploying new version..."
  DEPLOY_OUTPUT=$(clasp deploy -i "$GAS_DEPLOYMENT_ID" -d "auto-deploy $(date '+%Y-%m-%d %H:%M')" 2>&1)
  echo "$DEPLOY_OUTPUT"

  NEW_DEPLOYMENT_ID=$(echo "$DEPLOY_OUTPUT" | grep -oE 'AKfycb[A-Za-z0-9_\-]+' | head -1)

  # ────────────────────────────────────────────────
  # 4. אם ה-URL השתנה — עדכן .env + config.js
  # ────────────────────────────────────────────────
  if [ -n "$NEW_DEPLOYMENT_ID" ] && [ "$NEW_DEPLOYMENT_ID" != "$GAS_DEPLOYMENT_ID" ]; then
    NEW_URL="https://script.google.com/macros/s/$NEW_DEPLOYMENT_ID/exec"
    echo "🔄 URL changed → updating .env and config.js..."

    # עדכן .env
    sed -i '' "s|GAS_DEPLOYMENT_ID=.*|GAS_DEPLOYMENT_ID=$NEW_DEPLOYMENT_ID|" "$ENV_FILE"
    sed -i '' "s|GAS_URL=.*|GAS_URL=$NEW_URL|"                               "$ENV_FILE"
    echo "  Updated: .env"

    # עדכן config.js
    GAS_URL="$NEW_URL" bash "$REPO_DIR/build.sh"
    echo "🔗 New URL: $NEW_URL"
  else
    echo "✅ Same URL — no updates needed"
  fi
fi

# ────────────────────────────────────────────────
# 5. Git commit & push
# ────────────────────────────────────────────────
cd "$REPO_DIR"

if git diff --quiet && git diff --cached --quiet; then
  echo "✅ Nothing to commit"
else
  echo "📝 Committing..."
  git add -A
  git commit -m "deploy: update GAS $(date '+%Y-%m-%d %H:%M')"
  git push origin main
  echo "✅ Pushed to main"
fi

echo ""
echo "🎉 Done!"
