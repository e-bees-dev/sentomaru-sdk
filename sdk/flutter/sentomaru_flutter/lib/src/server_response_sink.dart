/// D-15c (review R I-1): how `SentomaruDioInterceptor` hands the final answer of a signed request to its
/// `SentomaruClient` without a public method an app could call to inject `server_response` events. This file is not
/// exported by `package:sentomaru_flutter/sentomaru_flutter.dart`.
library;

/// The client's receiver, registered by the client itself on construction.
final Expando<void Function(int? httpStatus, Object? data)> serverResponseSinks = Expando('sentomaru server responses');
