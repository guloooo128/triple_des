import Flutter
import Foundation
import CommonCrypto

public class SwiftTripleDesPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "triple_des", binaryMessenger: registrar.messenger())
        let instance = SwiftTripleDesPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        
        switch call.method {
        case "getPlatformVersion":
            result("iOS " + UIDevice.current.systemVersion)
        case "md5":
            if let text = call.arguments as? String {
                result(text.md5())
            } else {
                result("")
            }
        default:
            guard let arguments = call.arguments as? [String: Any] else {
                result(nil)
                return
            }
            
            let operation = call.method == "encrypt" ? kCCEncrypt : kCCDecrypt
            let key = arguments["key"] as? String ?? ""
            let iv = arguments["iv"] as? String ?? ""
            let options = arguments["options"] as? [UInt32] ?? []
            
            var data: Data = Data()
            
            if let flutterData = arguments["data"] as? FlutterStandardTypedData {
                data = flutterData.data
            } else if let text = arguments["text"] as? String,
                let textData = text.data(using: .utf8),
                let base64Data = Data(base64Encoded: textData) {
                data = base64Data
            }
            
            crypt(CCOperation(operation), data: data, key: key, iv: iv, options: options, result: result)
        }
    }
    
    private func crypt(_ operation: CCOperation, data: Data, key: String, iv: String, options: [UInt32], result: FlutterResult) {
        if let resultData = data.crypt(
            operation: operation,
            key: key,
            iv: iv,
            options: options) {
            if operation == kCCEncrypt {
                let text = resultData.base64EncodedString()
                print(text)
                result(resultData.base64EncodedString())
            } else {
                let text = String(data: resultData, encoding: .utf8)
                print(text)
                result(String(data: resultData, encoding: .utf8))
            }
        } else {
            result(nil)
        }
    }
}

private extension Data {
    func crypt(operation: CCOperation, key: String, iv: String, options: [UInt32]) -> Data? {
        
        var option: UInt32 = 0
        options.forEach{ option |= $0 }
        
        let dataInLength = self.count
        let dataBytes = self.withUnsafeBytes{ $0.baseAddress }
        
        guard let keyData = key.data(using: .utf8) else { return nil }
        let keyLength = kCCKeySize3DES
        let keyBytes = keyData.withUnsafeBytes{ $0.baseAddress }
        
        var dataOut = Data(count: dataInLength + kCCBlockSize3DES)
        let dataOutLength = dataOut.count
        guard let dataOutBytes = dataOut.withUnsafeMutableBytes({ $0.baseAddress }) else { return nil }
        
        guard let ivData = iv.data(using: .utf8) else { return nil }
        let ivBytes = ivData.withUnsafeBytes { $0.baseAddress }
        
        var dataOutMoved: Int = 0
        
        let cryptStatus = CCCrypt(
            operation, //mode/operation type (kCCEncrypt or kCCDecrypt)
            CCAlgorithm(kCCAlgorithm3DES),  //Algorithm type
            CCOptions(option),     //options
            keyBytes,                //Key (using not less than 8 bits)
            keyLength,
            ivBytes,
            dataBytes,                 //data to be encrypted/decrypted
            dataInLength,           //length of data to be encrypted/decrypted
            dataOutBytes,                //result of encryption/decryption
            dataOutLength,       //length of expected result
            &dataOutMoved)          //actual length of expected result
        
        if cryptStatus == kCCSuccess {
            let result = Data(bytes: dataOutBytes, count: dataOutMoved)
            return result
        } else {
            print("\(#function) error = \(cryptStatus)")
            return nil
        }
    }
}

private extension String {
    func md5() -> String{
        let utf8 = cString(using: .utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(utf8, CC_LONG(utf8!.count - 1), &digest)
        return digest.reduce("") { $0 + String(format:"%02x", $1) }
    }
}
