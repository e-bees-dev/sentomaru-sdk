import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// C-03a: the pin of an X.509 certificate in the profile format, `sha256/` + standard base64 of the SHA-256 of the
/// DER `SubjectPublicKeyInfo` (the same value `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst
/// -sha256 -binary | base64` gives). Null when [certificateDer] is not a DER certificate this minimal reader can walk.
String? spkiPin(Uint8List certificateDer) {
  final spki = subjectPublicKeyInfo(certificateDer);
  if (spki == null) return null;
  return 'sha256/${base64.encode(sha256.convert(spki).bytes)}';
}

/// The DER bytes (tag, length and value) of the `subjectPublicKeyInfo` of a DER X.509 certificate (RFC 5280 4.1), or
/// null on anything else. Minimal and strict: definite lengths only (DER), every length inside its parent, the
/// certificate exactly the whole input, the fields of `tbsCertificate` in their fixed order with their universal tags
/// (`[0] version` optional, `serialNumber`, `signature`, `issuer`, `validity`, `subject`, then the key).
Uint8List? subjectPublicKeyInfo(Uint8List der) {
  final cert = _Tlv.read(der, 0, der.length);
  if (cert == null || cert.tag != 0x30 || cert.end != der.length) return null;
  final tbs = _Tlv.read(der, cert.valueStart, cert.end);
  if (tbs == null || tbs.tag != 0x30) return null;
  var offset = tbs.valueStart;
  var field = _Tlv.read(der, offset, tbs.end);
  if (field != null && field.tag == 0xA0) {
    offset = field.end;
    field = _Tlv.read(der, offset, tbs.end);
  }
  // serialNumber INTEGER, then signature, issuer, validity and subject, all SEQUENCE.
  const expected = [0x02, 0x30, 0x30, 0x30, 0x30];
  for (final tag in expected) {
    if (field == null || field.tag != tag) return null;
    offset = field.end;
    field = _Tlv.read(der, offset, tbs.end);
  }
  if (field == null || field.tag != 0x30) return null;
  return Uint8List.sublistView(der, field.start, field.end);
}

class _Tlv {
  final int tag;
  final int start;
  final int valueStart;
  final int end;
  const _Tlv(this.tag, this.start, this.valueStart, this.end);

  /// One TLV at [start], fully inside [limit]; single-byte tags only (all X.509 fields read here are).
  static _Tlv? read(Uint8List bytes, int start, int limit) {
    if (start < 0 || start + 2 > limit || limit > bytes.length) return null;
    final tag = bytes[start];
    if (tag & 0x1F == 0x1F) return null;
    var offset = start + 1;
    final first = bytes[offset++];
    int length;
    if (first < 0x80) {
      length = first;
    } else {
      final count = first & 0x7F;
      // 0x80 is the indefinite length (BER, not DER); more than 4 length bytes cannot be a certificate here.
      if (count == 0 || count > 4 || offset + count > limit) return null;
      length = 0;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | bytes[offset++];
      }
      // DER: the shortest form (no leading zero byte, long form only from 128).
      if (length < 0x80 || (count > 1 && bytes[offset - count] == 0)) return null;
    }
    final end = offset + length;
    if (end > limit) return null;
    return _Tlv(tag, start, offset, end);
  }
}
