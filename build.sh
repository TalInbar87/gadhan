#!/bin/bash
# ================================================================
# build.sh — מייצר config.js מ-environment variables
# מופעל אוטומטית ע"י Vercel בכל deploy
# ================================================================

if [ -z "$GAS_URL" ] && [ -z "$SUPABASE_FUNCTION_URL" ]; then
  echo "❌ לפחות אחד מהם חייב להיות מוגדר: GAS_URL או SUPABASE_FUNCTION_URL"
  exit 1
fi

cat > config.js <<EOF
// ================================================================
// config.js — Auto-generated at build time. DO NOT EDIT MANUALLY.
// ================================================================
const API_URL              = '${GAS_URL:-}';
const SUPABASE_FUNCTION_URL = '${SUPABASE_FUNCTION_URL:-}';
EOF

echo "✅ config.js generated"
