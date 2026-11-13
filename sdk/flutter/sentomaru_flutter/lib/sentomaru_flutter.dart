import 'src/sentomaru_flutter_platform_interface.dart';

export 'src/enrollment_assurance.dart';
export 'src/exceptions.dart';
export 'src/models.dart';
export 'src/principal_store.dart';
export 'src/pinning/pinned_connection.dart' show SentomaruBadCertificateCallback;
export 'src/pinning/pinning_install.dart' show SentomaruPinningDioExtension, SentomaruPinningInstall;
export 'src/pinning/sentomaru_pins.dart'
    show SentomaruPins, SentomaruPinnedDomain, SentomaruTransportEvent, SentomaruTransportEventReason;
export 'src/reattestation.dart';
export 'src/sentomaru_capabilities.dart';
export 'src/sentomaru_client.dart';
export 'src/sentomaru_dio_interceptor.dart';
export 'src/sentomaru_routes.dart';
export 'src/sentomaru_sealed.dart';
export 'src/sentomaru_offline_chain.dart';
export 'src/sentomaru_transaction.dart';
export 'src/sentomaru_transaction_keys.dart';
export 'src/signal_events.dart';
export 'src/signals_snapshot.dart';
export 'src/user_message.dart';
export 'src/sentomaru_flutter_method_channel.dart';
export 'src/sentomaru_flutter_platform_interface.dart';

/// Legacy scaffold facade retained for backwards compatibility.
class SentomaruFlutter {
  Future<String?> scaffoldInfo() {
    return SentomaruFlutterPlatform.instance.scaffoldInfo();
  }
}
