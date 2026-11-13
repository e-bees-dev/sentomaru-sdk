import 'dart:developer';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Where [SentomaruEnrollmentAssurance] keeps the principal (sha256 of `subject\u0000tenant`) of whoever this
/// installation is enrolled for, so a later call can tell "reuse" from "someone else now" without the app storing
/// anything of its own (`sentomaru_flutter` 0.21.0, D-W-port).
///
/// The value lives in [FlutterSecureStorage] with a plain-text mirror in [SharedPreferences]: on Android the
/// encrypted store can lose its key or fail to decrypt (a partial write, a restore, a Keystore invalidation) and
/// come back empty even though the installation is still enrolled server-side; without the mirror that empty read
/// looked exactly like "a different caller now" and reset+enrolled a brand new installation for no reason (the bug
/// this class fixes, ported from an app-side principal store,
/// `claude/sentomaru-instalacao-reuso`). The mirror never authorizes anything by itself: [SentomaruEnrollmentAssurance]
/// only trusts it together with the plugin itself saying `enrolled`.
class SentomaruPrincipalStore {
  SentomaruPrincipalStore({FlutterSecureStorage? secure}) : _secure = secure ?? const FlutterSecureStorage();

  final FlutterSecureStorage _secure;

  static const secureKey = 'sentomaru_enrollment_principal';
  static const mirrorKey = 'sentomaru_enrollment_principal_mirror';

  Future<String?> read() async {
    String? secure;
    try {
      secure = await _secure.read(key: secureKey);
    } catch (_) {
      secure = null;
    }
    if (secure != null && secure.isNotEmpty) return secure;
    final mirror = await _prefs((p) async => p.getString(mirrorKey));
    if (mirror == null || mirror.isEmpty) return null;
    log('Sentomaru: principal recuperado da cópia de reserva', name: 'sentomaru');
    try {
      await _secure.write(key: secureKey, value: mirror);
    } catch (_) {
      // A cópia continua valendo na próxima leitura.
    }
    return mirror;
  }

  /// Grava nos dois lugares; a cópia primeiro, para que uma falha do armazenamento seguro não perca o principal.
  Future<void> write(String principal) async {
    await _prefs((p) => p.setString(mirrorKey, principal));
    try {
      await _secure.write(key: secureKey, value: principal);
    } catch (_) {
      // A cópia sozinha ainda permite reaproveitar a instalação na próxima leitura.
    }
  }

  Future<void> delete() async {
    await _prefs((p) => p.remove(mirrorKey));
    try {
      await _secure.delete(key: secureKey);
    } catch (_) {
      // Nada a fazer: a próxima leitura não encontra nenhuma das duas cópias.
    }
  }

  Future<T?> _prefs<T>(Future<T> Function(SharedPreferences) body) async {
    try {
      return await body(await SharedPreferences.getInstance());
    } catch (_) {
      return null;
    }
  }
}
