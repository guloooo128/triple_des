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
    
    private func crypt(_ operation: CCOperation, data: Data, key: String, iv: String, options: [UInt32], result: @escaping FlutterResult) {
        if let resultData = data.crypt(
            operation: operation,
            key: key,
            iv: iv,
            options: options) {
            if operation == kCCEncrypt {
                result(resultData.base64EncodedString())
            } else {
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
 
        guard let keyData = key.data(using: .utf8) else { return nil }

        guard let ivData = iv.data(using: .utf8) else { return nil }

        let resultData = crypt(
            operation: operation,
            algorithm: CCAlgorithm(kCCAlgorithm3DES),
            options: CCOptions(option),
            key: keyData,
            initializationVector: ivData,
            dataIn: self)
        
        return resultData
    }
    
    private func crypt(operation: UInt32, algorithm: UInt32, options: UInt32, key: Data, initializationVector: Data, dataIn: Data) -> Data? {
        return key.withUnsafeBytes { keyUnsafeRawBufferPointer in
            return dataIn.withUnsafeBytes { dataInUnsafeRawBufferPointer in
                return initializationVector.withUnsafeBytes { ivUnsafeRawBufferPointer in
                    // Give the data out some breathing room for PKCS7's padding.
                    let dataOutSize: Int = dataIn.count + kCCBlockSize3DES
                    let dataOut = UnsafeMutableRawPointer.allocate(byteCount: dataOutSize, alignment: 1)
                    defer { dataOut.deallocate() }
                    var dataOutMoved: Int = 0
                    let status = CCCrypt(
                        CCOperation(operation),
                        CCAlgorithm(algorithm),
                        CCOptions(options),
                        keyUnsafeRawBufferPointer.baseAddress,
                        size_t(kCCKeySize3DES),
                        ivUnsafeRawBufferPointer.baseAddress,
                        dataInUnsafeRawBufferPointer.baseAddress,
                        dataIn.count,
                        dataOut,
                        dataOutSize,
                        &dataOutMoved)
                    if status == kCCSuccess {
                        return Data(bytes: dataOut, count: dataOutMoved)
                    } else {
                        return nil
                    }
                }
            }
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
