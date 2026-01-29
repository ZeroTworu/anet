#!/bin/bash
# Build macOS app bundle for ANet VPN GUI
#
# Usage: ./scripts/build-macos-app.sh [--sign IDENTITY]
#
# Options:
#   --sign IDENTITY   Sign the app with the given code signing identity
#                     Example: --sign "Developer ID Application: Your Name (TEAMID)"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_NAME="ANet VPN"
BUNDLE_ID="com.anet.vpn.gui"
VERSION="0.1.0"

# Parse arguments
SIGN_IDENTITY=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --sign)
            SIGN_IDENTITY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Building ANet VPN macOS App Bundle..."
echo "Project root: $PROJECT_ROOT"

# Build the release binary
echo "Step 1: Building release binary..."
cd "$PROJECT_ROOT"
cargo build --release -p anet-client-gui

# Create app bundle structure
APP_BUNDLE="$PROJECT_ROOT/target/release/$APP_NAME.app"
CONTENTS="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

echo "Step 2: Creating app bundle structure..."
rm -rf "$APP_BUNDLE"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES"

# Copy binary
echo "Step 3: Copying binary..."
cp "$PROJECT_ROOT/target/release/anet-gui" "$MACOS_DIR/anet-gui"

# Copy Info.plist
echo "Step 4: Copying Info.plist..."
cp "$PROJECT_ROOT/anet-client-gui/macos/Info.plist" "$CONTENTS/Info.plist"

# Create PkgInfo
echo "Step 5: Creating PkgInfo..."
echo -n "APPL????" > "$CONTENTS/PkgInfo"

# Create a simple icon (placeholder - replace with actual icon)
echo "Step 6: Creating placeholder icon..."
# Note: For a real app, you should create a proper .icns file
# This creates a minimal placeholder

# Sign the app if identity provided
if [ -n "$SIGN_IDENTITY" ]; then
    echo "Step 7: Signing app bundle..."
    codesign --force --deep --sign "$SIGN_IDENTITY" \
        --entitlements "$PROJECT_ROOT/anet-client-gui/macos/entitlements.plist" \
        "$APP_BUNDLE"

    echo "Verifying signature..."
    codesign --verify --verbose "$APP_BUNDLE"
else
    echo "Step 7: Skipping code signing (no identity provided)"
    echo "  To sign, run: $0 --sign 'Your Developer ID'"
fi

echo ""
echo "App bundle created: $APP_BUNDLE"
echo ""
echo "To run the app:"
echo "  open '$APP_BUNDLE'"
echo ""
echo "Or run directly (requires sudo for VPN functionality):"
echo "  sudo '$MACOS_DIR/anet-gui'"
echo ""

if [ -z "$SIGN_IDENTITY" ]; then
    echo "Note: The app is unsigned. macOS may block it."
    echo "To allow unsigned apps, right-click and select 'Open',"
    echo "or run: xattr -cr '$APP_BUNDLE'"
fi
