//
//  Encryption.swift
//  CommonCryptoTool
//
//  Created by Brian Ortiz on 2023-08-11.
//

import Foundation
import CommonCrypto

class Encryption {
    
    static var shared = Encryption()
    
    private let key: Data
    private let iv: Data
    
    private let KEY_AES = "8a3abd470892c0f280c851ca45d31960"
    private let KEY_IV = "8a3abd470892c0f2"

    init() {
        let ivData = KEY_IV.data(using: .utf8) ?? Data()
        let keyData = KEY_AES.data(using: .utf8) ?? Data()
        
        self.key = keyData
        self.iv  = ivData
    }
    
    private func crypt(data: Data?, option: CCOperation) -> Data? {
        guard let data = data else { return nil }

        let cryptLength = data.count + kCCBlockSizeAES128
        var cryptData   = Data(count: cryptLength)

        let keyLength = key.count
        let options   = CCOptions(kCCOptionPKCS7Padding)

        var bytesLength = Int(0)

        let status = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                iv.withUnsafeBytes { ivBytes in
                    key.withUnsafeBytes { keyBytes in
                    CCCrypt(option, CCAlgorithm(kCCAlgorithmAES), options, keyBytes.baseAddress, keyLength, ivBytes.baseAddress, dataBytes.baseAddress, data.count, cryptBytes.baseAddress, cryptLength, &bytesLength)
                    }
                }
            }
        }

        guard UInt32(status) == UInt32(kCCSuccess) else {
            debugPrint("Error: Failed to crypt data. Status \(status)")
            return nil
        }

        cryptData.removeSubrange(bytesLength..<cryptData.count)
        return cryptData
    }
    
    func encrypt(text: String) -> String {
        guard let data = crypt(data: text.data(using: .utf8), option: CCOperation(kCCEncrypt)) else {
            return ""
        }
        return data.base64EncodedString()
    }

    func decrypt(text: String) -> String {
        let data = Data(base64Encoded: text)
        guard let decryptedData = crypt(data: data, option: CCOperation(kCCDecrypt)) else { return "error" }
        return String(bytes: decryptedData, encoding: .utf8) ?? ""
    }
    
}

