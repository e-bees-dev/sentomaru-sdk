import 'dart:developer';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'models.dart';
import 'principal_store.dart';
import 'sentomaru_client.dart';

/// Reinstalação no iOS: desinstalar não apaga o Keychain, onde o plugin guarda a inscrição e onde
/// [SentomaruPrincipalStore] guarda o principal, mas a chave do App Attest provavelmente não volta. Sem o marcador
/// de primeira execução (`SharedPreferences`/`UserDefaults`, que a desinstalação apaga), [SentomaruEnrollmentAssurance]
/// veria uma instalação "enrolled" com o principal certo e a reaproveitaria, assinando com uma chave que o App
/// Attest já não reconhece. Ported from an app-side reinstall guard.
///
/// Ordem: confere o estado primeiro — uma instalação nova neste aparelho (`notEnrolled` desde o início, nunca
/// instalada antes) não tem nada pra esquecer, então não gasta um `reset()` à toa; só uma instalação genuína
/// sobrevivente (qualquer outro estado) apaga o principal primeiro (sem ele a próxima chamada já decide por uma
/// inscrição nova) e depois `reset()` no plugin. O marcador só é gravado por último, nos dois casos. Falha só vai
/// para o log, sem marcador: a próxima chamada tenta de novo (idempotente, inclusive dentro do mesmo processo —
/// chame no início de toda operação que precisa da instalação certa; depois do marcador gravado é só uma leitura
/// de `SharedPreferences`). Fora do iOS não faz nada.
abstract final class SentomaruIosReinstallGuard {
  static const markerKey = 'sentomaru_enrollment_ios_installed';

  static Future<void> forgetIfReinstalled({
    required SentomaruClient client,
    required SentomaruPrincipalStore principalStore,
  }) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.iOS) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      if (prefs.getBool(markerKey) ?? false) return;
      if (await client.state() != InstallationState.notEnrolled) {
        await principalStore.delete();
        await client.reset();
        log('Sentomaru: primeira execução no iOS; instalação antiga esquecida', name: 'sentomaru');
      }
      await prefs.setBool(markerKey, true);
    } catch (e) {
      log(
        'Sentomaru: limpeza da reinstalação falhou (${e.runtimeType}); tenta na próxima chamada',
        name: 'sentomaru',
      );
    }
  }
}
