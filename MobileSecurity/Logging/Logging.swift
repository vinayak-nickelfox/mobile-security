//
//  Logging.swift
//  MobileSecurity
//
//  Created by Vinayak Paul on 20/11/22.
//

import Foundation

func print(_ items: Any..., separator: String = " ", terminator: String = "\n") {
    
#if DEBUG
    var idx = items.startIndex
    let endIdx = items.endIndex
    repeat {
        Swift.print(
            items[idx],
            separator: separator,
            terminator: idx == (endIdx - 1) ? terminator : separator
        )
        
        idx += 1
    }
    while idx < endIdx
            #endif
}
