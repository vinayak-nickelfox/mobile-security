//
//  ViewController.swift
//  MobileSecurity
//
//  Created by Vinayak Paul on 19/11/22.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet weak var imageView: UIImageView!
    @IBOutlet weak var label: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.setupUI()
    }
    
    
    func setupUI() {
        let isJailBroken = JailbreakManager.shared.isJailBroken()
        
        let sosImage = UIImage(systemName: "exclamationmark.triangle.fill")
        let verifiedImage = UIImage(systemName: "checkmark.seal.fill")
        let sos = "Your device has been compromised under Jailbreak!"
        let verified = "Device under protected ecosystem"
        
        self.imageView.image = isJailBroken ? sosImage : verifiedImage
        self.imageView.tintColor = isJailBroken ? .red : .systemBlue
        self.label.text = isJailBroken ? sos : verified
        
    }

}


extension ViewController {
    
}
