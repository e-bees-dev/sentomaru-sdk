#
# iOS side of the Sentomaru Flutter plugin, over the Swift SDK of sdk/ios.
#
# CocoaPods, not SwiftPM: Flutter 3.41.9 (the line of the CI) builds iOS plugins with CocoaPods unless
# the app opts in to Swift Package Manager (CocoaPods is the default); an app that opts in falls back to CocoaPods
# for a plugin without a Package.swift (Flutter's documented behaviour, not tested here). One pod is one module, so
# the SDK sources (SentomaruCore + Sentomaru) are compiled into this pod's module through the symlinks under
# Classes/SDK, one per file of sdk/ios/Sources of the same checkout (a pub `git:` dependency checks out the whole
# repository, as the Android build's default Maven path already assumes). One link per file because CocoaPods does not
# descend into a symlinked directory; test/ios_sdk_sources_test.dart fails when a file of sdk/ios/Sources has no link
# here or a link points nowhere. No binary, no third-party pod: Foundation, CryptoKit, Security and DeviceCheck only.
#
Pod::Spec.new do |s|
  s.name             = 'sentomaru_flutter'
  s.version          = '0.20.0-rc.6'
  s.summary          = 'Sentomaru Flutter adapter: RFC 9421 signing with App Attest and the Secure Enclave on iOS.'
  s.description      = <<-DESC
iOS side of the Sentomaru Flutter plugin: the same method channel as Android, delegating to the Swift SDK (sdk/ios).
                       DESC
  s.homepage         = 'https://github.com/e-bees-dev/sentomaru-sdk'
  s.license          = { :type => 'Proprietary', :text => 'Proprietary. Copyright e-bees.' }
  s.author           = { 'e-bees' => 'sentomaru@ebees.com.br' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*.swift'
  s.dependency 'Flutter'
  s.platform         = :ios, '15.0'
  s.frameworks       = 'CryptoKit', 'DeviceCheck', 'LocalAuthentication', 'Security'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  # Same language mode as sdk/ios/Package.swift (swiftLanguageModes: [.v6]).
  s.swift_version = '6.0'

  # No tracking, no collected data, no required-reason API (Keychain, Secure Enclave and App Attest are not on the list).
  s.resource_bundles = { 'sentomaru_flutter_privacy' => ['Resources/PrivacyInfo.xcprivacy'] }
end
