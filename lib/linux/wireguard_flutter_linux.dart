import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:process_run/shell.dart';

import '../wireguard_flutter_platform_interface.dart';

/// Linux: drives `wg-quick` / `wg` from wireguard-tools through `sudo`.
///
/// Requirements on the host: `wireguard-tools` (wg, wg-quick), a `resolvconf` (systemd-resolved ships a shim) for the
/// `DNS=` line, and passwordless sudo for `wg` and `wg-quick` (or the app running as root). The config is written to
/// `<tmp>/<interfaceName>.conf` with mode 0600 (it holds the private key) and removed again once the tunnel is down.
class WireGuardFlutterLinux extends WireGuardFlutterInterface {
  String? name;
  String? tunnelName;
  File? configFile;

  VpnStage _stage = VpnStage.noConnection;
  final _stageController = StreamController<VpnStage>.broadcast();
  void _setStage(VpnStage stage) {
    _stage = stage;
    _stageController.add(stage);
  }

  final shell = Shell(runInShell: true, verbose: kDebugMode);

  @override
  Future<void> initialize({
    required String interfaceName,
    String? vpnName,
    String? iosAppGroup,
    String? extensionBundleId,
  }) async {
    name = interfaceName.replaceAll(' ', '_');
    tunnelName = interfaceName;
    await refreshStage();
  }

  @override
  Future<void> requestMacSystemExtension(String bundleId) {
    throw UnimplementedError('System extensions are only supported on macOS');
  }

  Future<String> get filePath async {
    final tempDir = await getTemporaryDirectory();
    return '${tempDir.path}${Platform.pathSeparator}$name.conf';
  }

  /// Writes the wg-quick config readable by the owner only (it contains the private key).
  Future<File> _writeConfig(String wgQuickConfig) async {
    final file = File(await filePath);
    await file.create();
    await Process.run('chmod', ['600', file.path]);
    await file.writeAsString(wgQuickConfig, flush: true);
    return file;
  }

  Future<void> _deleteConfig() async {
    final f = configFile ?? File(await filePath);
    try {
      if (await f.exists()) await f.delete();
    } catch (e) {
      debugPrint('wireguard: could not remove ${f.path}: $e');
    }
  }

  @override
  Future<void> startVpn({
    required String serverAddress,
    required String wgQuickConfig,
    required String providerBundleIdentifier,
    List<String>? excludedApps,
    List<String>? includedApps,
  }) async {
    final isAlreadyConnected = await isConnected();
    if (!isAlreadyConnected) {
      _setStage(VpnStage.preparing);
    } else {
      debugPrint('Already connected');
    }

    try {
      configFile = await _writeConfig(wgQuickConfig);
    } on PathAccessException {
      debugPrint('Denied to write file. Trying to start interface');
      if (isAlreadyConnected) {
        return _setStage(VpnStage.connected);
      }

      try {
        await shell.run('sudo wg-quick up $name');
      } catch (_) {
      } finally {
        _setStage(VpnStage.denied);
      }
    }

    if (!isAlreadyConnected) {
      _setStage(VpnStage.connecting);
      try {
        await shell.run('sudo wg-quick up ${configFile?.path ?? await filePath}');
      } catch (e) {
        await _deleteConfig();
        await refreshStage();
        rethrow;
      }
      _connectedAt = DateTime.now();
      _lastSample = null;
      _setStage(VpnStage.connected);
    }
  }

  @override
  Future<void> stopVpn() async {
    if (!await isConnected()) {
      debugPrint('stopVpn: no tunnel "$name" is up');
      await _deleteConfig();
      await refreshStage();
      return;
    }
    _setStage(VpnStage.disconnecting);
    try {
      await shell.run('sudo wg-quick down ${configFile?.path ?? (await filePath)}');
    } catch (e) {
      await refreshStage();
      rethrow;
    }
    _connectedAt = null;
    _lastSample = null;
    await _deleteConfig();
    await refreshStage();
  }

  @override
  Future<VpnStage> stage() async => _stage;

  @override
  Stream<VpnStage> get vpnStageSnapshot => _stageController.stream;

  @override
  Future<void> refreshStage() async {
    if (await isConnected()) {
      _setStage(VpnStage.connected);
    } else if (name == null) {
      _setStage(VpnStage.waitingConnection);
    } else if (configFile == null) {
      _setStage(VpnStage.noConnection);
    } else {
      _setStage(VpnStage.disconnected);
    }
  }

  @override
  Future<bool> isConnected() async {
    assert(name != null, 'Bad state: not initialized. Call "initialize" before calling this command');
    final processResultList = await shell.run('sudo wg show interfaces');
    final process = processResultList.first;
    return process.outLines.expand((line) => line.trim().split(RegExp(r'\s+'))).any((iface) => iface == name);
  }

  // ---- traffic ------------------------------------------------------------------------------------------------

  DateTime? _connectedAt;
  ({DateTime at, int rx, int tx})? _lastSample;

  /// Polls `wg show <iface> transfer` every 2 s while the tunnel is up and emits the same map the Android engine
  /// sends: `totalDownload`/`totalUpload` in KiB, `downloadSpeed`/`uploadSpeed` in KiB/s, `duration` as HH:MM:SS.
  @override
  Stream<Map<String, dynamic>> get trafficSnapshot async* {
    if (tunnelName == null) {
      throw Exception("Tunnel name is not initialized. Call initialize() first.");
    }
    while (true) {
      await Future.delayed(const Duration(seconds: 2));
      final trafficData = await _fetchTrafficData();
      if (trafficData != null) {
        yield trafficData;
      }
    }
  }

  Future<Map<String, dynamic>?> _fetchTrafficData() async {
    if (_stage != VpnStage.connected) return null;
    try {
      // One line per peer: "<peer public key>\t<rx bytes>\t<tx bytes>"
      final result = await shell.run('sudo wg show $name transfer');
      var rx = 0, tx = 0;
      for (final line in result.first.outLines) {
        final cols = line.trim().split('\t');
        if (cols.length < 3) continue;
        rx += int.tryParse(cols[1]) ?? 0;
        tx += int.tryParse(cols[2]) ?? 0;
      }
      final now = DateTime.now();
      var downBps = 0.0, upBps = 0.0;
      final last = _lastSample;
      if (last != null) {
        final secs = now.difference(last.at).inMilliseconds / 1000.0;
        if (secs > 0) {
          downBps = (rx - last.rx).clamp(0, 1 << 62) / secs;
          upBps = (tx - last.tx).clamp(0, 1 << 62) / secs;
        }
      }
      _lastSample = (at: now, rx: rx, tx: tx);
      final up = _connectedAt == null ? Duration.zero : now.difference(_connectedAt!);
      String two(int v) => v.toString().padLeft(2, '0');
      return {
        'totalDownload': rx / 1024,
        'totalUpload': tx / 1024,
        'downloadSpeed': downBps / 1024,
        'uploadSpeed': upBps / 1024,
        'duration': '${two(up.inHours)}:${two(up.inMinutes.remainder(60))}:${two(up.inSeconds.remainder(60))}',
      };
    } catch (e) {
      debugPrint('Error fetching traffic data: $e');
    }
    return null;
  }

  @override
  Future<bool> checkVpnPermission() async {
    // No system VPN consent on Linux; the only prerequisite is that `sudo wg` works without a prompt.
    try {
      final r = await shell.run('sudo -n wg --version');
      return r.first.exitCode == 0;
    } catch (_) {
      return false;
    }
  }
}
