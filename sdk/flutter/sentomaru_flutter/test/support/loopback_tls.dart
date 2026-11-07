// Test-only TLS identity for loopback servers (self-signed, CN=localhost, password "password").
// Same throwaway fixture as sdk/android OkHttpTransportTest; it protects nothing and is not a secret.
import 'dart:convert';
import 'dart:io';

const String _pkcs12B64 =
    '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';

SecurityContext loopbackServerContext() {
  final bytes = base64Decode(_pkcs12B64);
  return SecurityContext()
    ..useCertificateChainBytes(bytes, password: 'password')
    ..usePrivateKeyBytes(bytes, password: 'password');
}
