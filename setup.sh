#!/data/data/com.termux/files/usr/bin/bash
echo "════════════════════════════"
echo "  ✦ تثبيت ذكاء v2"
echo "════════════════════════════"
pkg update -y && pkg upgrade -y
pkg install nodejs -y
cd backend && npm install && cd ..
echo ""
echo "✅ اكتمل التثبيت!"
echo ""
echo "الخطوة التالية:"
echo "  nano backend/.env"
echo "  ← حط مفتاحك، ثم Ctrl+X ثم Y"
echo ""
echo "تشغيل السيرفر:"
echo "  bash start.sh"
