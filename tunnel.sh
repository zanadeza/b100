#!/data/data/com.termux/files/usr/bin/bash
echo "✦ توليد رابط عام..."
command -v lt &>/dev/null || npm install -g localtunnel
RAND=$((RANDOM % 9000 + 1000))
echo ""
echo "رابطك العام سيكون جاهز بثوانٍ..."
echo ""
lt --port 3000 --subdomain zaka-${RAND}
