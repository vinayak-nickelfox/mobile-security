//
//  ConventionalConfig.swift
//  MobileSecurity
//
//  Created by Vinayak Paul on 20/11/22.
//

import Foundation

struct ConventionalConfig {
    
    static var apiKey: String {
        #if DEBUG
        return "1234-dev-1234"
        #else
        return "5678-prod-5678"
        #endif
    }
}
