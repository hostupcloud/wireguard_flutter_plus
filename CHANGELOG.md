## 1.0.12

* Android: `startVpn` always brings UP a fresh tunnel handle carrying the call's state callback. Previously a cached handle created without a callback (the traffic monitor polls `getStatistics(tunnel(name))`, and a kill-switch block counts as an active VPN) was reused, so the UP event never reached Dart and reconnecting from the kill-switch block appeared to hang.
* Android: the traffic monitor is not started while the kill-switch block is up (there is no tunnel to read).

## 1.0.11

* Android: register the activity-result listener so the VPN consent dialog's answer reaches the plugin; the first connect on a fresh install no longer hangs after the user taps OK. A pending consent is failed (not left hanging) when the activity detaches.

## 1.0.10
* **Android kill switch**:
  * `setKillSwitch(bool)` / `isKillSwitchEnabled()` persist the setting in the engine. While enabled, a tunnel that goes DOWN without our own stop (OS revoke, stopped from system settings, engine crash) starts `KillSwitchVpnService`: a blocking VPN session (10.255.255.1/32, routes 0.0.0.0/0 + ::/0, black-hole DNS) with a foreground notification "Kill switch active" and a "Turn off kill switch" action.
  * New `VpnStage.blocked`, emitted on the stage stream and returned by `stage()` while the block is up.
  * `clearBlock()` releases the block; `startVpn` releases it on its own before the tunnel establishes.
  * iOS/macOS/Windows/Linux: `killSwitchSupported == false`, all kill switch calls are no-ops.

## 1.0.9
* **macOS & Darwin Network Architecture**:
  * Resolved macOS App Sandbox UDP bind failure (`listen udp4 :0: bind: operation not permitted`) by adding incoming network server privileges (`com.apple.security.network.server`), enabling full download and bidirectional network throughput.
  * Added dynamic endpoint host resolution from `wgQuickConfig` to `protocolConfiguration.serverAddress`, allowing standard cross-platform WireGuard configs (`AllowedIPs = 0.0.0.0/0, ::/0`) without routing loops on macOS.
  * Fixed macOS `cfprefsd` container detaching error (`Using kCFPreferencesAnyUser with a container is only allowed for System Containers`) by safely guarding `UserDefaults(suiteName:)` on macOS and utilizing direct IPC (`sendProviderMessage`) and standard sandboxed defaults.
* **Duration Continuity & State Resilience**:
  * Infallible duration tracking leveraging Apple's native `NEVPNConnection.connectedDate`, ensuring session duration does not reset to `00:00:00` when the Flutter app is reopened or hot-restarted while connected.
  * Fixed stream cancellation (`onCancel`) erasing session timestamps and emitting reset events while the tunnel is actively running in the background.
  * Paused background timers on stream cancellation (`onCancel`) to save CPU and battery when no active listener exists.
* **Packet Tunnel Provider & Documentation**:
  * Added automatic IPv6 safety filtering in `PacketTunnelProvider` to strip `::/0` from peer allowed IPs when interface is IPv4-only, avoiding route configuration failures.
  * Integrated unified Apple `os_log` tracing in `PacketTunnelProvider` for real-time debugging via macOS Console or `log stream`.
  * Updated `ios_setup_readme.md` with comprehensive macOS entitlements, setup guide, troubleshooting steps, and the latest resilient `PacketTunnelProvider` implementation.

## 1.0.8
* **macOS/Darwin Concurrency & Traffic Resilience**:
  * Fixed an event channel race condition where canceling the VPN stage subscription (`wgstage`) killed the traffic monitoring timer (`traffic`).
  * Thread-safe `TrafficStreamHandler` state synchronization using a dedicated serial dispatch queue.
  * Infallible duration tracking leveraging Apple `NEVPNConnection.connectedDate` with safe fallback to `UserDefaults` timestamp.
  * Added initial speed spike filtering (`isFirstTickAfterResume`) so cumulative bytes transferred during app suspension/reconnect are not reported as a 1-second instantaneous burst.
  * Paused background IPC timer on stream cancellation (`onCancel`) to save CPU and battery when no active listener exists.
  * Removed main-thread blocking `DispatchSemaphore` in `currentStatus()` to prevent UI freezes, watchdog terminations, and initialization deadlocks.
  * Dynamic App Group fallback to standard `UserDefaults` when unconfigured to prevent sandboxing container lookup errors.
* **Extension & Documentation**:
  * Added fallback in `PacketTunnelProvider.handleAppMessage` to return runtime configuration stats if network interface query returns empty across iOS, macOS, and System Extensions.
  * Updated `ios_setup_readme.md` with the latest resilient packet tunnel implementation.

## 1.0.7
* Fixed iOS native code returning 0 for traffic stats on very first VPN connection.
* Fixed Dart layer mapping `VpnStage.denied` to `VpnStage.disconnected`.

## 1.0.6
* Added Split Tunneling feature (includedApps/excludedApps) support for Android and Linux.

## 1.0.5
* Fixed Android 16KB page size crash by updating WireGuard Tunnel dependency.

## 1.0.4
* Add VPN Server Hub banners to README.md.

## 1.0.3
* Add Windows support.
* Add support crypto address in README.md.

## 1.0.2
* Improve package description.
* Update dependencies.
* Add API documentation.

## 1.0.1
* Added dynamic iOS App Group ID support.
* Updated iOS setup documentation.
* Renamed example to standard 'example' directory.

## 0.1.0

* Fixed android connection state.

## 0.0.9

* Remove unused code.

## 0.0.7

* Remove unused permission.

## 0.0.4

* Add example.

## 0.0.3

* Initial Open Source release.
