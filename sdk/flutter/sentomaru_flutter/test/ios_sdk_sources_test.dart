import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// D-10b: the iOS pod compiles the Swift SDK (sdk/ios/Sources) through one symlink per file under ios/Classes/SDK
/// (CocoaPods does not descend into a symlinked directory). A file added to the SDK without its link would leave the
/// plugin without it (a build error at best); a link to a removed file would break the pod.
void main() {
  const modules = ['SentomaruCore', 'Sentomaru'];
  final sdk = Directory('../../ios/Sources');

  /// Every `.swift` under [dir], recursively, as a path relative to it (a subfolder in the SDK needs its links too).
  List<String> swiftNames(Directory dir) => dir
      .listSync(recursive: true, followLinks: false)
      .where((e) => e.path.endsWith('.swift'))
      .map((e) => e.path.substring(dir.path.length + 1))
      .toList()
    ..sort();

  test('the SDK sources are where the links expect them', () {
    expect(sdk.existsSync(), isTrue, reason: 'run from sdk/flutter/sentomaru_flutter in a full checkout');
  });

  for (final module in modules) {
    test('ios/Classes/SDK/$module links exactly the files of sdk/ios/Sources/$module', () {
      final sources = swiftNames(Directory('${sdk.path}/$module'));
      final linkDir = Directory('ios/Classes/SDK/$module');
      expect(sources, isNotEmpty);
      expect(swiftNames(linkDir), sources);
      for (final name in sources) {
        final link = Link('${linkDir.path}/$name');
        expect(link.existsSync(), isTrue, reason: '$name is not a symlink');
        final up = '../' * (6 + name.split('/').length - 1);
        expect(link.targetSync(), '${up}ios/Sources/$module/$name', reason: 'relative link, same checkout');
        expect(File(link.path).resolveSymbolicLinksSync(), File('${sdk.path}/$module/$name').resolveSymbolicLinksSync());
      }
    });
  }
}
