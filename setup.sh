#!/data/data/com.termux/files/usr/bin/bash
echo "Installing MedTerm..."
cd "$(dirname "$0")/backend"
npm install
echo "Done! Run: bash start.sh"
