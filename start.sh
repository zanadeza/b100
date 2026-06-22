#!/data/data/com.termux/files/usr/bin/bash
echo ""
echo "✦ جاري تشغيل ذكاء v2..."
echo ""
cd "$(dirname "$0")/backend"
node server.js
