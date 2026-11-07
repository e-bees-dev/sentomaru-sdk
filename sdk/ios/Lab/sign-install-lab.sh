#!/bin/bash
# D-27 iOS proof (laboratory): signs out/SentomaruLab.app with an EXISTING development profile (no -allowProvisioningUpdates, no new
# App ID) and installs it on ONE device. Needs the owner's go-ahead: with the ExampleApp bundle id it REPLACES the installed ExampleApp.
# usage: sign-install-lab.sh <profile.mobileprovision> <codesign identity sha1> <device udid>
# The profile and the certificate are only read by security/codesign (never printed); entitlements are the profile's own.
set -euo pipefail
cd "$(dirname "$0")"
PROFILE=$1; IDENTITY=$2; DEVICE=$3
APP=out/SentomaruLab.app
security cms -D -i "$PROFILE" | plutil -extract Entitlements xml1 -o out/entitlements.plist -
cp "$PROFILE" "$APP/embedded.mobileprovision"
codesign --force --sign "$IDENTITY" --entitlements out/entitlements.plist --timestamp=none "$APP"
codesign --verify --strict "$APP"
xcrun devicectl device install app --device "$DEVICE" "$APP"
