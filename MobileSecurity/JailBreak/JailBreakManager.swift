//
//  JailBreakManager.swift
//  MobileSecurity
//
//  Created by Vinayak Paul on 20/11/22.
//

import MachO
import UIKit

final class JailbreakManager{
    
    static let shared: JailbreakManager = .init()
    
    private init(){ }
    
    // Facade method
    func isJailBroken()-> Bool{
        if isRunOnSimulator() { return false }
        
        return self.checkPaths() || ///Detect suspicious path
               self.checkSchemes() || /// Detect suspicious schemes
               self.canViolateSandbox() ||
               self.checkSymlinks() || /// check system files
               self.checkDylibs() || /// detect dylib
               self.checkSuspiciousFilesCanBeOpened() ||
               self.canFork() /// Sandbox denies forking if jailbreak
    }
    
}

// MARK: Private methods
extension JailbreakManager {
    
    private func pathsToCheck()-> [String] {
        return [
            "/.bootstrapped_electra",
            "/.cydia_no_stash",
            "/.installed_unc0ver",
            "/Applications/Cydia.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/Sileo.app",
            "/Applications/Snoop-itConfig.app",
            "/Applications/WinterBoard.app",
            "/Applications/blackra1n.app",
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/PreferenceBundles/ABypassPrefs.bundle",
            "/Library/PreferenceBundles/FlyJBPrefs.bundle",
            "/Library/PreferenceBundles/LibertyPref.bundle",
            "/Library/PreferenceBundles/ShadowPreferences.bundle",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/bin/bash",
            "/bin/sh",
            "/etc/apt",
            "/etc/apt/sources.list.d/electra.list",
            "/etc/apt/sources.list.d/sileo.sources",
            "/etc/apt/undecimus/undecimus.list",
            "/etc/ssh/sshd_config",
            "/jb/amfid_payload.dylib",
            "/jb/jailbreakd.plist",
            "/jb/libjailbreak.dylib",
            "/jb/lzma",
            "/jb/offsets.plist",
            "/private/etc/apt",
            "/private/etc/dpkg/origins/debian",
            "/private/etc/ssh/sshd_config",
            "/private/var/Users/",
            "/private/var/cache/apt/",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/log/syslog",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/var/tmp/cydia.log",
            "/usr/bin/cycript",
            "/usr/bin/sshd",
            "/usr/lib/libcycript.dylib",
            "/usr/lib/libhooker.dylib",
            "/usr/lib/libjailbreak.dylib",
            "/usr/lib/libsubstitute.dylib",
            "/usr/lib/substrate",
            "/usr/lib/TweakInject",
            "/usr/libexec/cydia",
            "/usr/libexec/cydia/firmware.sh",
            "/usr/libexec/sftp-server",
            "/usr/libexec/ssh-keysign",
            "/usr/local/bin/cycript",
            "/usr/sbin/frida-server",
            "/usr/sbin/sshd",
            "/usr/share/jailbreak/injectme.plist",
            "/var/binpack",
            "/var/cache/apt",
            "/var/checkra1n.dmg",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/var/lib/dpkg/info/mobilesubstrate.md5sums",
            "/var/log/apt"
        ]
    }
    
    private func schemesToCheck()-> [String] {
        return [
            "activator://package/com.example.package",
            "cydia://package/com.example.package",
            "filza://package/com.example.package",
            "sileo://package/com.example.package",
            "undecimus://package/com.example.package",
            "zbra://package/com.example.package"
        ]
    }
    
    private func symlinksToCheck() -> [String] {
        return [
            "/var/lib/undecimus/apt",
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]
    }
    
    
    private func dylibsToCheck() -> [String] {
        return [
            "...!@#",
            "/.file",
            "/usr/lib/Cephei.framework/Cephei",
            "0Shadow.dylib",
            "ABypass",
            "Cephei",
            "CustomWidgetIcons",
            "CydiaSubstrate",
            "Electra",
            "FlyJB",
            "FridaGadget",
            "MobileSubstrate.dylib",
            "PreferenceLoader",
            "RocketBootstrap",
            "SSLKillSwitch.dylib",
            "SSLKillSwitch2.dylib",
            "Substitute",
            "SubstrateBootstrap",
            "SubstrateInserter",
            "SubstrateInserter.dylib",
            "SubstrateLoader.dylib",
            "TweakInject.dylib",
            "WeeLoader",
            "cyinject",
            "libcycript",
            "libhooker",
            "libsparkapplist.dylib",
            "zzzzLiberty.dylib",
            "zzzzzzUnSub.dylib"
        ];
    }
    
    private func checkPaths()-> Bool {
        var existsPath = false
        
        for path in self.pathsToCheck() {
            if FileManager.default.fileExists(atPath: path){
                //print("jailbreak path exists", path)
                existsPath = true
                break
            }
        }
        
        return existsPath
    }
    
    private func canOpenUrlFromList(urlSchemes: [String])-> Bool {
        var canOpenScheme = false
        
        for scheme in self.schemesToCheck() {
            if let url = URL(string: scheme){
                if UIApplication.shared.canOpenURL(url){
                    //print("jailbreak can open url scheme", scheme)
                    canOpenScheme = true
                    break
                }
            }
            
            
        }
        return canOpenScheme
    }
    
    private func checkSchemes()-> Bool {
        var flag = false
        let urlSchemes = self.schemesToCheck()
        
        if Thread.isMainThread {
            flag = canOpenUrlFromList(urlSchemes: urlSchemes)
        } else {
            let semaphore = DispatchSemaphore(value: 0)
            DispatchQueue.main.async {
                flag = self.canOpenUrlFromList(urlSchemes: urlSchemes)
                semaphore.signal()
            }
            semaphore.wait()
        }
        return flag
    }
    
    private func checkSuspiciousFilesCanBeOpened() -> Bool {
        let paths = [
            "/.installed_unc0ver",
            "/.bootstrapped_electra",
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/etc/apt",
            "/var/log/apt",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/usr/bin/ssh"
        ]
        
        for path in paths {
            if FileManager.default.isReadableFile(atPath: path) {
                // print("jailbreak file opened", path)
                return true
            }
        }
        return false
    }
    
    private func checkDylibs()-> Bool {
        for i in 0..<_dyld_image_count()  {
            guard let imagePath = String(
                validatingUTF8:(_dyld_get_image_name(i))
            ) else {
                continue
            }
            
            for dylibPath in self.dylibsToCheck() {
                if imagePath.lowercased().contains(
                    dylibPath.lowercased()
                ) {
                    //print("jailbreak dylib", dylibPath)
                    return true
                }
            }
        }
        return false
    }
    
    private func canViolateSandbox()-> Bool{
        let paths = [
            "/",
            "/root/",
            "/private/",
            "/jb/"
        ]
        
        for path in paths {
            do {
                let pathWithSomeRandom = path+UUID().uuidString
                
                try "AmIJailbroken?".write(
                    toFile: pathWithSomeRandom,
                    atomically: true,
                    encoding: String.Encoding.utf8
                )
                
                try FileManager.default.removeItem(
                    atPath: pathWithSomeRandom
                )
                //print("jailbreak violate sandbox", path)
                return true
            } catch {}
        }
        
        return false
    }
    
    private func canFork() -> Bool {
        let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
        let forkPtr = dlsym(pointerToFork, "fork")
        typealias ForkType = @convention(c) () -> pid_t
        let fork = unsafeBitCast(forkPtr, to: ForkType.self)
        let forkResult = fork()
        
        if forkResult >= 0 {
            if forkResult > 0 {
                kill(forkResult, SIGTERM)
            }
            //print("jailbreak can fork")
            return true
        }
        return false
    }
    
    private func checkSymlinks() -> Bool {
        for symlink in self.symlinksToCheck() {
            do {
                let result = try FileManager.default.destinationOfSymbolicLink(
                    atPath: symlink
                )
                if !result.isEmpty {
                    //print("jailbreak symlink", symlink)
                    return true
                }
            } catch {}
        }
        
        return false
    }
    
    private func isRunOnSimulator() -> Bool {
        checkCompile() || checkRuntime()
    }
    
    private func checkRuntime() -> Bool {
        ProcessInfo().environment["SIMULATOR_DEVICE_NAME"] != nil
    }
    
    private func checkCompile() -> Bool {
        #if targetEnvironment(simulator)
                return true
        #else
                return false
        #endif
    }
}
