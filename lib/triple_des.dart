
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter/services.dart';

class TripleDes {
  static const MethodChannel _channel = const MethodChannel('triple_des');

  static Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  static Future<String> md5(String text) async {
    final String result = await _channel.invokeMethod("md5", text);
    return result;
  }

  /// Decrypt a text with the Triple DES.
  ///
  /// The [options] can be 1 = PKCS7Padding, 2 = ECBMode, or both.
  static Future<String> encryptWithText(String text, String key, { iv = "", List<int> options }) async {
    return await encryptWithData(utf8.encode(text), key, iv: iv, options: options);
  }

  /// Decrypt a text with the Triple DES.
  ///
  /// The [options] can be 1 = PKCS7Padding, 2 = ECBMode, or both.
  static Future<String> encryptWithData(Uint8List data, String key, { iv = "", List<int> options }) async {
    final String result = await _channel.invokeMethod("encrypt", {"data": data, "key": key, "options": options});
    return result;
  }

  /// Decrypt a text with the Triple DES.
  ///
  /// The [options] can be 1 = PKCS7Padding, 2 = ECBMode, or both.
  static Future<String> decryptWithData(Uint8List data, String key, { iv = "", List<int> options }) async {
    final String result = await _channel.invokeMethod("decrypt", {"data": data, "key": key, "options": options});
    return result;
  }

  /// Decrypt a text with the Triple DES.
  ///
  /// The [options] can be 1 = PKCS7Padding, 2 = ECBMode, or both.
  static Future<String> decryptWithText(String text, String key, { iv = "", List<int> options }) async {
    final String result = await _channel.invokeMethod("decrypt", {"text": text, "key": key, "options": options});
    return result;
  }
}
