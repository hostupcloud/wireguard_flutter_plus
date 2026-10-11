#if os(iOS)
import Flutter
import UIKit
#elseif os(macOS)
import FlutterMacOS
import Cocoa
import SystemExtensions
#else
#error("Unsupported platform")
#endif

import NetworkExtension
import Foundation
import Network

public class WireguardFlutterPlugin: NSObject, FlutterPlugin {
    static var utils: VPNUtils! = VPNUtils()
    public static var stage: FlutterEventSink?
    private var initialized: Bool = false
    var wireguardMethodChannel: FlutterMethodChannel?
    private var systemExtensionResult: FlutterResult?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = WireguardFlutterPlugin()
        instance.onRegister(registrar)
    }

    public func onRegister(_ registrar: FlutterPluginRegistrar){
        #if os(iOS)
        let messenger = registrar.messenger()
        #else
        let messenger = registrar.messenger
        #endif

        let wireguardMethodChannel = FlutterMethodChannel(name: "orban.group.wireguard_flutter_plus/wgcontrol", binaryMessenger: messenger)
        let vpnStageE = FlutterEventChannel(name: "orban.group.wireguard_flutter_plus/wgstage", binaryMessenger: messenger)
        let trafficChannel = FlutterEventChannel(name: "orban.group.wireguard_flutter_plus/traffic", binaryMessenger: messenger)

        trafficChannel.setStreamHandler(TrafficStreamHandler.shared)
        vpnStageE.setStreamHandler(VPNConnectionHandler())

        wireguardMethodChannel.setMethodCallHandler({ (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
            switch call.method {
            case "stage":
                result(WireguardFlutterPlugin.utils.currentStatus())
            case "initialize":
                guard let localizedDescription = (call.arguments as? [String: Any])?["localizedDescription"] as? String else {
                    result(FlutterError(code: "-3", message: "localizedDescription content empty or null", details: nil))
                    return
                }
                if let groupId = (call.arguments as? [String: Any])?["groupId"] as? String, !groupId.isEmpty {
                    TrafficStreamHandler.shared.configure(groupId: groupId)
                    WireguardFlutterPlugin.utils.groupIdentifier = groupId
                }
                if let extensionBundleId = (call.arguments as? [String: Any])?["extensionBundleId"] as? String {
                    WireguardFlutterPlugin.utils.providerBundleIdentifier = extensionBundleId
                }
                WireguardFlutterPlugin.utils.localizedDescription = localizedDescription
                WireguardFlutterPlugin.utils.loadProviderManager { err in
                    if err == nil {
                        result(WireguardFlutterPlugin.utils.currentStatus())
                    } else {
                        result(FlutterError(code: "-4", message: err?.localizedDescription, details: err?.localizedDescription))
                    }
                }
                self.initialized = true
            case "stop":
                self.disconnect(result: result)
            case "start":
                guard let args = call.arguments as? [String: Any],
                      let serverAddress = args["serverAddress"] as? String,
                      let wgQuickConfig = args["wgQuickConfig"] as? String,
                      let providerBundleIdentifier = args["providerBundleIdentifier"] as? String else {
                    result(FlutterError(code: "-5", message: "Invalid arguments", details: nil))
                    return
                }
                self.connect(serverAddress: serverAddress, wgQuickConfig: wgQuickConfig, providerBundleIdentifier: providerBundleIdentifier, result: result)
            case "dispose":
                self.initialized = false
                result(nil)
            case "requestMacSystemExtension":
                #if os(macOS)
                guard let args = call.arguments as? [String: Any],
                      let bundleId = args["bundleId"] as? String else {
                    result(FlutterError(code: "-5", message: "Invalid arguments", details: nil))
                    return
                }
                if #available(macOS 10.15, *) {
                    self.systemExtensionResult = result
                    let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: bundleId, queue: .main)
                    request.delegate = self
                    OSSystemExtensionManager.shared.submitRequest(request)
                } else {
                    result(FlutterError(code: "-6", message: "System Extensions require macOS 10.15 or later", details: nil))
                }
                #else
                result(FlutterError(code: "-6", message: "System Extensions are only supported on macOS", details: nil))
                #endif
            default:
                result(FlutterMethodNotImplemented)
            }
        })
    }

    private func connect(serverAddress: String, wgQuickConfig: String, providerBundleIdentifier: String, result: @escaping FlutterResult) {
        WireguardFlutterPlugin.utils.configureVPN(serverAddress: serverAddress, wgQuickConfig: wgQuickConfig, providerBundleIdentifier: providerBundleIdentifier) { success in
            if success {
                TrafficStreamHandler.shared.resetSession()
                TrafficStreamHandler.shared.startMonitoring()
            }
            result(success)
        }
    }

    private func disconnect(result: @escaping FlutterResult) {
        WireguardFlutterPlugin.utils.stopVPN { success in
            TrafficStreamHandler.shared.resetSession()
            result(success)
        }
    }
}

class TrafficStreamHandler: NSObject, FlutterStreamHandler {
    static let shared = TrafficStreamHandler()
    private let queue = DispatchQueue(label: "group.wireguard.traffic_handler", qos: .utility)
    private var eventSink: FlutterEventSink?
    private var timer: DispatchSourceTimer?
    private var lastDownload: Int64 = 0
    private var lastUpload: Int64 = 0
    private var isFirstTickAfterResume: Bool = true
    private var sessionStartDate: Date?
    private var groupId: String?

    private var defaults: UserDefaults {
        if let gid = groupId, !gid.isEmpty, let groupDefaults = UserDefaults(suiteName: gid) {
            return groupDefaults
        }
        return UserDefaults.standard
    }
    
    func configure(groupId: String) {
        queue.async {
            self.groupId = groupId
        }
    } 

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        queue.async {
            self.eventSink = events
            self.isFirstTickAfterResume = true
            
            let isConnected = WireguardFlutterPlugin.utils.currentStatus() == "connected"
            if isConnected {
                self.startMonitoringInternal()
            } else {
                self.stopTimerInternal()
                let idleTraffic: [String: Any] = [
                    "downloadSpeed": 0,
                    "uploadSpeed": 0,
                    "totalDownload": 0,
                    "totalUpload": 0,
                    "duration": "00:00:00"
                ]
                DispatchQueue.main.async { [weak self] in
                    self?.eventSink?(idleTraffic)
                }
            }
        }
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        queue.async {
            self.eventSink = nil
            self.stopTimerInternal()
        }
        return nil
    }

    func startMonitoring() {
        queue.async {
            let isConnected = WireguardFlutterPlugin.utils.currentStatus() == "connected"
            guard isConnected else { return }
            self.startMonitoringInternal()
        }
    }

    private func startMonitoringInternal() {
        let isConnected = WireguardFlutterPlugin.utils.currentStatus() == "connected"
        guard isConnected else {
            stopTimerInternal()
            return
        }

        // Restore last known totals or default to 0
        lastDownload = (defaults.object(forKey: "vpn_last_download") as? Int64) ?? 0
        lastUpload = (defaults.object(forKey: "vpn_last_upload") as? Int64) ?? 0

        let durationStr = currentFormattedDuration()

        let initialTraffic: [String: Any] = [
            "downloadSpeed": 0,
            "uploadSpeed": 0,
            "totalDownload": lastDownload,
            "totalUpload": lastUpload,
            "duration": durationStr
        ]
        DispatchQueue.main.async { [weak self] in
            self?.eventSink?(initialTraffic)
        }

        guard timer == nil else { return }

        let timerSource = DispatchSource.makeTimerSource(queue: queue)
        timerSource.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timerSource.setEventHandler { [weak self] in
            self?.tick()
        }
        timer = timerSource
        timerSource.resume()
    }

    private func tick() {
        let isConnected = WireguardFlutterPlugin.utils.currentStatus() == "connected"
        guard isConnected else {
            self.resetSessionInternal()
            return
        }

        var currentDownload: Int64 = 0
        var currentUpload: Int64 = 0
        var hasNewStats = false

        if let stats = WireguardFlutterPlugin.utils.getTrafficStats() {
            if let rx = stats["rxBytes"] as? Int64, let tx = stats["txBytes"] as? Int64 {
                currentDownload = rx
                currentUpload = tx
                hasNewStats = true
            } else if let rx = stats["totalDownload"] as? Double, let tx = stats["totalUpload"] as? Double {
                currentDownload = Int64(rx * 1024)
                currentUpload = Int64(tx * 1024)
                hasNewStats = true
            }
        } else {
            let defDownload = defaults.object(forKey: "totalDownloadBytes") as? Int64 ?? 0
            let defUpload = defaults.object(forKey: "totalUploadBytes") as? Int64 ?? 0
            if defDownload > 0 || defUpload > 0 {
                currentDownload = defDownload
                currentUpload = defUpload
                hasNewStats = true
            }
        }

        let downloadSpeed: Int64
        let uploadSpeed: Int64

        if hasNewStats {
            if isFirstTickAfterResume || (lastDownload == 0 && lastUpload == 0) {
                // Baseline calibration: prevents burst spikes across app restarts or background wakeups
                downloadSpeed = 0
                uploadSpeed = 0
                isFirstTickAfterResume = false
            } else {
                downloadSpeed = max(currentDownload - lastDownload, 0)
                uploadSpeed = max(currentUpload - lastUpload, 0)
            }

            lastDownload = currentDownload
            lastUpload = currentUpload

            defaults.set(lastDownload, forKey: "vpn_last_download")
            defaults.set(lastUpload, forKey: "vpn_last_upload")
        } else {
            downloadSpeed = 0
            uploadSpeed = 0
        }

        let formattedDuration = currentFormattedDuration()

        let traffic: [String: Any] = [
            "downloadSpeed": downloadSpeed,
            "uploadSpeed": uploadSpeed,
            "totalDownload": lastDownload,
            "totalUpload": lastUpload,
            "duration": formattedDuration
        ]

        DispatchQueue.main.async { [weak self] in
            self?.eventSink?(traffic)
        }
    }

    private func currentFormattedDuration() -> String {
        let isConnected = WireguardFlutterPlugin.utils.currentStatus() == "connected"
        guard isConnected else {
            return "00:00:00"
        }

        if sessionStartDate == nil {
            if let connectedDate = WireguardFlutterPlugin.utils.providerManager?.connection.connectedDate {
                sessionStartDate = connectedDate
            } else if let saved = (defaults.object(forKey: "vpn_session_start_time") as? NSNumber)?.doubleValue, saved > 0 {
                sessionStartDate = Date(timeIntervalSince1970: saved)
            } else if let vpnStart = WireguardFlutterPlugin.utils.vpnStartTime {
                sessionStartDate = vpnStart
            } else {
                sessionStartDate = Date()
            }

            if let start = sessionStartDate {
                defaults.set(start.timeIntervalSince1970, forKey: "vpn_session_start_time")
                defaults.synchronize()
            }
        }

        let elapsedSeconds = max(0, Int(Date().timeIntervalSince(sessionStartDate ?? Date())))
        return formatDuration(TimeInterval(elapsedSeconds))
    }

    func resetSession() {
        queue.async {
            self.resetSessionInternal()
        }
    }

    private func resetSessionInternal() {
        self.stopTimerInternal()
        self.lastDownload = 0
        self.lastUpload = 0
        self.isFirstTickAfterResume = true
        self.sessionStartDate = nil
        WireguardFlutterPlugin.utils.vpnStartTime = nil

        self.defaults.removeObject(forKey: "vpn_session_start_time")
        self.defaults.removeObject(forKey: "vpn_last_download")
        self.defaults.removeObject(forKey: "vpn_last_upload")
        self.defaults.synchronize()

        DispatchQueue.main.async { [weak self] in
            let resetTraffic: [String: Any] = [
                "downloadSpeed": 0,
                "uploadSpeed": 0,
                "totalDownload": 0,
                "totalUpload": 0,
                "duration": "00:00:00"
            ]
            self?.eventSink?(resetTraffic)
        }
    }

    private func stopTimerInternal() {
        timer?.cancel()
        timer = nil
    }

    func stopMonitoring() {
        queue.async {
            self.stopTimerInternal()
        }
    }

    private func formatDuration(_ interval: TimeInterval) -> String {
        let totalSeconds = Int(interval)
        let hours = totalSeconds / 3600
        let minutes = (totalSeconds % 3600) / 60
        let seconds = totalSeconds % 60
        return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }
}

class VPNConnectionHandler: NSObject, FlutterStreamHandler {
    private var vpnConnection: FlutterEventSink?
    private var vpnConnectionObserver: NSObjectProtocol?

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        self.vpnConnection = events
        if let observer = vpnConnectionObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        vpnConnectionObserver = NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] notification in
            guard let self = self, 
                  let connection = self.vpnConnection else { return }
            let status = (notification.object as? NEVPNConnection)?.status
            let statusStr = WireguardFlutterPlugin.utils.onVpnStatusChangedString(notification: status)
            connection(statusStr)
           
            if status == .connected {
                TrafficStreamHandler.shared.startMonitoring()
            } else if status == .disconnected || status == .invalid {
                TrafficStreamHandler.shared.resetSession()
            }
        }

        // Emit current status immediately without blocking
        let current = WireguardFlutterPlugin.utils.currentStatus()
        events(current)
        if current == "connected" {
            TrafficStreamHandler.shared.startMonitoring()
        } else {
            TrafficStreamHandler.shared.resetSession()
        }

        // Asynchronously warm up the provider manager if not yet loaded
        if WireguardFlutterPlugin.utils.providerManager == nil {
            WireguardFlutterPlugin.utils.loadProviderManager { [weak self] _ in
                DispatchQueue.main.async {
                    guard let self = self, let connection = self.vpnConnection else { return }
                    let updated = WireguardFlutterPlugin.utils.currentStatus()
                    connection(updated)
                    if updated == "connected" {
                        TrafficStreamHandler.shared.startMonitoring()
                    } else {
                        TrafficStreamHandler.shared.resetSession()
                    }
                }
            }
        }
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        if let observer = vpnConnectionObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        vpnConnectionObserver = nil
        vpnConnection = nil
        return nil
    }
}

@available(iOS 15.0, *)
class VPNUtils {
    var providerManager: NETunnelProviderManager!
    var providerBundleIdentifier: String?
    var localizedDescription: String?
    var groupIdentifier: String?
    var serverAddress: String?
    var stage: FlutterEventSink!

    private var lastDownloadBytes: Int64 = 0
    private var lastUploadBytes: Int64 = 0
    private var lastUpdateTime: Date?
    var vpnStartTime: Date?

    func loadProviderManager(completion: @escaping (_ error: Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
            if error == nil {
                self.providerManager = managers?.first ?? NETunnelProviderManager()
                completion(nil)
            } else {
                completion(error)
            }
        }
    }

    func onVpnStatusChangedString(notification: NEVPNStatus?) -> String {
        switch notification {
        case .connected: return "connected"
        case .connecting: return "connecting"
        case .disconnected: return "disconnected"
        case .disconnecting: return "disconnecting"
        case .invalid: return "invalid"
        case .reasserting: return "reasserting"
        default: return "disconnected"
        }
    }

    func currentStatus() -> String {
        guard let manager = providerManager else {
            return "disconnected"
        }
        return onVpnStatusChangedString(notification: manager.connection.status)
    }

    func getTrafficStats() -> [String: Any]? {
        guard let session = providerManager?.connection as? NETunnelProviderSession else { return nil }
        guard session.status == .connected else { return nil }

        let semaphore = DispatchSemaphore(value: 0)
        var resultDict: [String: Any]?
        let messageData = "getStats".data(using: .utf8)!

        do {
            try session.sendProviderMessage(messageData) { response in
                defer { semaphore.signal() }

                guard let response = response,
                      let dict = try? JSONSerialization.jsonObject(with: response) as? [String: UInt64],
                      let rxBytes = dict["rx"],
                      let txBytes = dict["tx"] else {
                    return
                }

                resultDict = [
                    "rxBytes": Int64(rxBytes),
                    "txBytes": Int64(txBytes),
                    "totalDownload": Double(rxBytes) / 1024.0,
                    "totalUpload": Double(txBytes) / 1024.0
                ]
            }
        } catch {
            print("Error sending provider message: \(error)")
            semaphore.signal()
        }

        _ = semaphore.wait(timeout: .now() + 1.0)
        return resultDict
    }

    func configureVPN(serverAddress: String?, wgQuickConfig: String?, providerBundleIdentifier: String?, completion: @escaping (Bool) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                print("Error (loadAllFromPreferences): \(error)")
                completion(false)
                return
            }

            let tunnelManager = managers?.first ?? NETunnelProviderManager()
            let protocolConfiguration = NETunnelProviderProtocol()
            protocolConfiguration.providerBundleIdentifier = providerBundleIdentifier
            protocolConfiguration.serverAddress = serverAddress
            protocolConfiguration.providerConfiguration = ["wgQuickConfig": wgQuickConfig ?? ""]
            tunnelManager.protocolConfiguration = protocolConfiguration
            tunnelManager.localizedDescription = self.localizedDescription
            tunnelManager.isEnabled = true

            tunnelManager.saveToPreferences { error in
                if let error = error {
                    print("Error (saveToPreferences): \(error)")
                    completion(false)
                } else {
                    tunnelManager.loadFromPreferences { error in
                        if let error = error {
                            print("Error (loadFromPreferences): \(error)")
                            completion(false)
                        } else if let session = tunnelManager.connection as? NETunnelProviderSession {
                            do {
                                try session.startTunnel(options: nil)
                                self.vpnStartTime = Date() 
                                self.providerManager = tunnelManager
                                completion(true)
                            } catch {
                                print("Error (startTunnel): \(error)")
                                completion(false)
                            }
                        } else {
                            completion(false)
                        }
                    }
                }
            }
        }
    }

    func stopVPN(completion: @escaping (Bool?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let session = managers?.first?.connection as? NETunnelProviderSession {
                switch session.status {
                case .connected, .connecting, .reasserting:
                    session.stopTunnel()
                    completion(true)
                default:
                    completion(false)
                }
            } else {
                completion(false)
            }
        }
    }

    private func formatDuration(_ interval: TimeInterval) -> String {
     let totalSeconds = Int(interval)
     let hours = totalSeconds / 3600
     let minutes = (totalSeconds % 3600) / 60
     let seconds = totalSeconds % 60
     return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }

}

#if os(macOS)
@available(macOS 10.15, *)
extension WireguardFlutterPlugin: OSSystemExtensionRequestDelegate {
    public func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("System Extension replacement request: replacing \(existing.bundleVersion) with \(ext.bundleVersion)")
        return .replace
    }
    
    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("System Extension requires user approval in Privacy & Security settings.")
    }
    
    public func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print("System Extension successfully installed.")
        self.systemExtensionResult?(true)
        self.systemExtensionResult = nil
    }
    
    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("System Extension installation failed with error: \(error.localizedDescription)")
        self.systemExtensionResult?(FlutterError(code: "-7", message: "System Extension failed to install", details: error.localizedDescription))
        self.systemExtensionResult = nil
    }
}
#endif
