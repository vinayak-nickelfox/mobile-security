//
//  Config.swift
//  MobileSecurity
//
//  Created by Vinayak Paul on 20/11/22.
//

import Foundation

enum ConfigError: Error {
    case missingKey, invalidValue
}

struct Config {

    static func value<T: LosslessStringConvertible>(for key: String) throws -> T  {
        
        guard let object = Bundle.main.object(forInfoDictionaryKey:key) else {
            throw ConfigError.missingKey
        }

        switch object {
        case let value as T:
            return value
        case let value as String:
            guard let value = T(value) else { fallthrough }
            return value
        default:
            throw ConfigError.invalidValue
        }
    }
}

