# Cordova example

`www/index.html` and `www/js/index.js`: after `deviceready` a button runs `www/js/flow.js` on `window.Sentomaru` (the plugin clobbers it): initialize, state, enroll, sign, signals snapshot. Values are placeholders; the challenge comes from your server.

What runs here (no device): `npm test` (the flow through the real Cordova facade with a fake native, 2 tests).

What does NOT run here: `cordova platform add android`, `cordova plugin add ../`, the Gradle build with `sdk/hybrid-core` packaged into the app (the plugin.xml says this is not proven), an install on a device, a call to a server.
