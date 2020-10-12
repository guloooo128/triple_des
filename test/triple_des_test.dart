import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:triple_des/triple_des.dart';

void main() {
  const MethodChannel channel = MethodChannel('triple_des');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await TripleDes.platformVersion, '42');
  });
}
