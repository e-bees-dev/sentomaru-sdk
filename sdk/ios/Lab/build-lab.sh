#!/bin/bash
# D-27 iOS proof (laboratory): builds SentomaruLab.app for a device with swiftc (no Xcode project). Signing and installing are
# separate steps (sign-install-lab.sh) and need the owner's go-ahead for the device. Output: Lab/out/SentomaruLab.app (unsigned).
set -euo pipefail
cd "$(dirname "$0")"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
T=arm64-apple-ios15.0
OUT=out; rm -rf "$OUT"; mkdir -p "$OUT/mods" "$OUT/SentomaruLab.app"
common=(-sdk "$SDK" -target $T -O -swift-version 6 -parse-as-library)
xcrun swiftc "${common[@]}" -module-name SentomaruCore -emit-module -emit-module-path "$OUT/mods/SentomaruCore.swiftmodule" \
  -wmo -c ../Sources/SentomaruCore/*.swift -o "$OUT/core.o"
xcrun swiftc "${common[@]}" -I "$OUT/mods" -module-name Sentomaru -emit-module -emit-module-path "$OUT/mods/Sentomaru.swiftmodule" \
  -wmo -c ../Sources/Sentomaru/*.swift -o "$OUT/sdk.o"
xcrun swiftc "${common[@]}" -I "$OUT/mods" -module-name SentomaruLab -c "${LAB_MAIN:-main.swift}" -o "$OUT/lab.o"
xcrun swiftc -sdk "$SDK" -target $T "$OUT/core.o" "$OUT/sdk.o" "$OUT/lab.o" -o "$OUT/SentomaruLab.app/SentomaruLab" \
  -framework UIKit -framework Foundation -framework Security -framework DeviceCheck -framework CryptoKit
cp Info.plist "$OUT/SentomaruLab.app/Info.plist"
echo "built $OUT/SentomaruLab.app (unsigned)"
