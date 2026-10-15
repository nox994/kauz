#!/usr/bin/env bash
# Adds Kauz to your app menu (only for your user, no root needed).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
REPO="$(pwd)"

if ! python3 -c "import PySide6.QtSvgWidgets" 2>/dev/null; then
    echo "PySide6 is missing. Install it first, e.g. on CachyOS/Arch:  sudo pacman -S pyside6"
    exit 1
fi

# Prefer an installed kauz-gui command, otherwise start straight from this folder.
if command -v kauz-gui >/dev/null; then
    EXEC="$(command -v kauz-gui)"
else
    EXEC="env PYTHONPATH=\"$REPO\" python3 -m kauz.gui"
fi

APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"
mkdir -p "$APPS" "$ICONS"
install -m644 data/kauz.svg "$ICONS/kauz.svg"
sed "s|^Exec=.*|Exec=$EXEC|" data/kauz.desktop > "$APPS/kauz.desktop"
chmod 644 "$APPS/kauz.desktop"
update-desktop-database "$APPS" 2>/dev/null || true

echo "🦉 Kauz is now in your app menu (category: System)."
echo "   If you move this folder, run ./install-desktop.sh again."
