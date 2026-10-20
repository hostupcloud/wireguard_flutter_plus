package orban.group.wireguard_flutter
import orban.group.wireguard_flutter.config.WgQuickParser
import orban.group.wireguard_flutter.config.WgQuickConfig

import java.io.StringReader
import android.content.pm.ServiceInfo


import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.PluginRegistry

import android.app.Activity
import io.flutter.embedding.android.FlutterActivity
import android.content.BroadcastReceiver
import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import com.beust.klaxon.Klaxon
// import com.wireguard.android.backend.*
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.BackendException
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import com.wireguard.config.Config

import io.flutter.plugin.common.EventChannel
import kotlinx.coroutines.*
import java.util.*

import java.io.BufferedReader

import android.net.VpnService

import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream




import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat


/** WireguardFlutterPlugin */

const val PERMISSIONS_REQUEST_CODE = 10014
const val METHOD_CHANNEL_NAME = "orban.group.wireguard_flutter_plus/wgcontrol"
const val METHOD_EVENT_NAME = "orban.group.wireguard_flutter_plus/wgstage"
const val TRAFFIC_EVENT_NAME = "orban.group.wireguard_flutter_plus/traffic"

class WireguardFlutterPlugin : FlutterPlugin, MethodCallHandler, ActivityAware,
    PluginRegistry.ActivityResultListener {
    private lateinit var channel: MethodChannel
    private lateinit var events: EventChannel
    private lateinit var trafficEvents: EventChannel
    private lateinit var context: Context

    private var trafficMonitorJob: Job? = null

 
    private val futureBackend = CompletableDeferred<Backend>()
    private var vpnStageSink: EventChannel.EventSink? = null
    private var trafficSink: EventChannel.EventSink? = null
    private val scope = CoroutineScope(Job() + Dispatchers.Main.immediate)
    // Backend/tunnel/config live in the companion: one per PROCESS, not per Flutter engine. A reopened app
    // (new engine, same process, service still holding the tunnel) must see the running tunnel.
    private var backend: Backend?
        get() = sharedBackend
        set(v) { sharedBackend = v }
    private var havePermission = false
    private var permissionResult: MethodChannel.Result? = null
    private var vpnPermissionContinuation: ((Boolean) -> Unit)? = null

    private var previousRx: Long = 0
    private var previousTx: Long = 0
    private var lastUpdateTime: Long = 0
    private var trafficMonitorActive = false
    private var connectionStartTime: Long = 0L  // 👈 ADD THIS LINE
    private var activity: Activity? = null

    private var tunnelName: String
        get() = sharedTunnelName ?: "wg0"
        set(v) { sharedTunnelName = v }
    private var vpnDisplayName: String = "WireGuard VPN" // Custom VPN display name
    private var config: com.wireguard.config.Config?
        get() = sharedConfig
        set(v) { sharedConfig = v }
    private var tunnel: WireGuardTunnel?
        get() = sharedTunnel
        set(v) { sharedTunnel = v }
    private val TAG = "NVPN"
    var isVpnChecked = false
    companion object {
        /** Broadcast action of the notification "Disconnect" button (handled by [VpnDisconnectReceiver] in this process). */
        const val ACTION_DISCONNECT = "orban.group.wireguard_flutter.ACTION_DISCONNECT"
        /** Broadcast action of the kill-switch notification "Turn off kill switch" button. */
        const val ACTION_KILL_SWITCH_OFF = "orban.group.wireguard_flutter.ACTION_KILL_SWITCH_OFF"
        private const val LOG_TAG = "NVPN"
        private const val PREF_KILL_SWITCH = "kill_switch"
        /** How long after our own DOWN request a DOWN callback still counts as expected (it is synchronous in practice). */
        private const val EXPECTED_DOWN_WINDOW_MS = 10_000L

        /** Application context, kept so the kill switch can act with no Flutter engine attached. */
        @Volatile private var appContext: Context? = null
        /** elapsedRealtime() until which a DOWN callback is ours (stop/restart) and must not trigger the kill switch. */
        @Volatile private var expectedDownUntil = 0L

        private var state: String = "no_connection"
        @Volatile private var sharedBackend: Backend? = null
        @Volatile private var sharedTunnel: WireGuardTunnel? = null
        @Volatile private var sharedConfig: com.wireguard.config.Config? = null
        @Volatile private var sharedTunnelName: String? = null
        /** The plugin attached to the live Flutter engine, or null while the app UI is closed (service keeps the tunnel). */
        @Volatile private var instance: WireguardFlutterPlugin? = null
        private val processScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        fun getStatus(): String {
            return state
        }

        // --- kill switch -------------------------------------------------------------------------------------------

        fun isKillSwitchEnabled(context: Context): Boolean =
            context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE).getBoolean(PREF_KILL_SWITCH, false)

        /** Persists the user's choice. Turning it off also releases an active block. */
        fun setKillSwitchEnabled(context: Context, enabled: Boolean) {
            val app = context.applicationContext
            appContext = app
            app.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE).edit().putBoolean(PREF_KILL_SWITCH, enabled).apply()
            Log.i(LOG_TAG, "Kill switch ${if (enabled) "enabled" else "disabled"}")
            if (!enabled) clearBlock(app)
        }

        /** Marks the next DOWN as ours. Call right before any setState(DOWN) issued by this plugin. */
        internal fun expectDown() {
            expectedDownUntil = SystemClock.elapsedRealtime() + EXPECTED_DOWN_WINDOW_MS
        }

        /**
         * Every engine state change of every [WireGuardTunnel] lands here first. A DOWN that we did not ask for (OS
         * revoked the VPN, user stopped it in Settings, wireguard-go died) engages the block when the kill switch is on.
         */
        internal fun onTunnelState(newState: Tunnel.State) {
            if (newState == Tunnel.State.UP) {
                expectedDownUntil = 0L
                return
            }
            if (newState != Tunnel.State.DOWN) return
            val ctx = appContext ?: return
            if (SystemClock.elapsedRealtime() < expectedDownUntil) {
                expectedDownUntil = 0L
                return
            }
            if (!isKillSwitchEnabled(ctx)) return
            Log.w(LOG_TAG, "Tunnel went DOWN unexpectedly with the kill switch on: blocking all traffic")
            engageBlock(ctx)
        }

        /** Starts the blocking session and retires the tunnel's foreground service/notification. */
        private fun engageBlock(context: Context) {
            val inst = instance
            inst?.stopTrafficMonitor()
            inst?.resetTrafficStats()
            state = "blocked"
            // Start the block while the tunnel's foreground service is still alive: the process counts as foreground,
            // so the foreground start is allowed even with the app UI closed.
            KillSwitchVpnService.start(context)
            VpnForegroundService.stop(context)
            clearStatsFromStorage(context)
            clearLastUsedConfig(context)
            sharedTunnel = null
            inst?.updateStage("blocked")
        }

        /** Releases the block (before a reconnect, or when the kill switch is turned off). */
        fun clearBlock(context: Context) {
            val wasBlocked = KillSwitchVpnService.isRunning || state == "blocked"
            KillSwitchVpnService.stop(context.applicationContext)
            if (wasBlocked && state == "blocked") {
                state = "disconnected"
                instance?.updateStage("disconnected")
            }
        }

        /** The blocking session is established (reported by [KillSwitchVpnService]). */
        internal fun onBlockEngaged() {
            state = "blocked"
            instance?.updateStage("blocked")
        }

        /** The blocking session ended on its own: revoked by another VPN, or it could not be established. */
        internal fun onBlockReleased(failed: Boolean) {
            if (failed) Log.e(LOG_TAG, "Kill switch block could not be established; traffic is NOT blocked")
            if (state == "blocked") {
                state = "disconnected"
                instance?.updateStage("disconnected")
            }
        }

        /**
         * Notification "Disconnect": the same teardown as the Dart "stop" method ([tearDownTunnel]), but runnable with no
         * Flutter engine attached. Stops the foreground service and, when a Dart listener exists, emits "disconnected"
         * on the stage EventChannel (a reopened app asks the backend via "stage" and gets the truth anyway).
         */
        fun disconnectFromNotification(context: Context, onDone: () -> Unit = {}) {
            val app = context.applicationContext
            processScope.launch {
                val inst = instance
                var stillUp = false
                try {
                    inst?.stopTrafficMonitor()
                    inst?.resetTrafficStats()
                    state = "disconnecting"
                    inst?.updateStage("disconnecting")
                    val backend = sharedBackend
                    if (backend == null) {
                        Log.w(LOG_TAG, "Notification disconnect: no backend in this process, nothing to bring down")
                    } else {
                        tearDownTunnel(app, backend) { st -> instance?.updateStageFromState(st) }
                    }
                } catch (e: Throwable) {
                    Log.e(LOG_TAG, "Notification disconnect failed: ${e.message}", e)
                    stillUp = try { sharedBackend?.runningTunnelNames?.isNotEmpty() == true } catch (t: Throwable) { false }
                }
                if (stillUp) {
                    // Tunnel survived: keep the service/notification, tell Dart the truth.
                    state = "connected"
                    instance?.updateStage("connected")
                    onDone()
                    return@launch
                }
                VpnForegroundService.stop(app)
                clearStatsFromStorage(app)
                clearLastUsedConfig(app)
                sharedTunnel = null
                sharedConfig = null
                state = "disconnected"
                instance?.updateStage("disconnected")
                Log.i(LOG_TAG, "Disconnected from notification")
                onDone()
            }
        }

        /**
         * Brings the running tunnel DOWN using the per-process singletons. Shared by the Dart "stop" method and the
         * notification action. Throws when the tunnel is still up afterwards. Returns true when a tunnel was running.
         */
        @Throws(Exception::class)
        internal fun tearDownTunnel(context: Context, backend: Backend, onState: StateChangeCallback): Boolean {
            val runningTunnels = backend.runningTunnelNames
            Log.i(LOG_TAG, "Running tunnels: $runningTunnels")
            Log.i(LOG_TAG, "Current tunnelName: ${sharedTunnelName ?: "wg0"}")

            // Load config if not already loaded
            if (sharedConfig == null) {
                val prefs = context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE)
                val savedConfigString = prefs.getString("last_used_config", null)
                if (!savedConfigString.isNullOrEmpty()) {
                    sharedConfig = com.wireguard.config.Config.parse(savedConfigString.byteInputStream())
                    Log.i(LOG_TAG, "Loaded config from SharedPreferences for disconnect")
                }
            }
            val config = sharedConfig

            if (runningTunnels.isNotEmpty()) {
                val activeTunnelName = runningTunnels.first()
                Log.i(LOG_TAG, "Disconnecting tunnel: $activeTunnelName")
                if (config == null) {
                    Log.e(LOG_TAG, "Config is null, cannot call setState() for disconnect")
                    throw Exception("Cannot disconnect: no configuration available")
                }

                // Get or create tunnel object
                var t = sharedTunnel
                if (t == null) {
                    Log.i(LOG_TAG, "Creating new tunnel object for disconnect")
                    sharedTunnelName = activeTunnelName
                    t = WireGuardTunnel(activeTunnelName, onState)
                    sharedTunnel = t
                } else {
                    Log.i(LOG_TAG, "Reusing existing tunnel object for disconnect")
                }

                Log.i(LOG_TAG, "About to call backend.setState() with Tunnel.State.DOWN")
                expectDown()
                backend.setState(t, Tunnel.State.DOWN, config)
                Log.i(LOG_TAG, "backend.setState() call completed")
                // GoBackend only brings DOWN the exact Tunnel object it brought UP. If our handle is stale (process
                // re-attach, earlier failure), the call above is a silent no-op: verify and force it.
                if (backend.runningTunnelNames.contains(activeTunnelName)) {
                    Log.w(LOG_TAG, "Tunnel still running after DOWN (stale handle) - forcing UP/DOWN with the current config")
                    try {
                        val fresh = WireGuardTunnel(activeTunnelName, onState)
                        sharedTunnel = fresh
                        backend.setState(fresh, Tunnel.State.UP, config)   // re-registers currentTunnel = fresh
                        expectDown()
                        backend.setState(fresh, Tunnel.State.DOWN, null)
                    } catch (e: Throwable) {
                        Log.e(LOG_TAG, "Forced DOWN failed: ${e.message}", e)
                    }
                    if (backend.runningTunnelNames.contains(activeTunnelName)) throw Exception("Tunnel could not be stopped")
                }
                Log.i(LOG_TAG, "Tunnel $activeTunnelName disconnected")
                return true
            }

            // No running tunnels reported by backend, but we may have tunnel and config (app reopen): the backend does
            // not know about this tunnel, so bring it UP first then immediately DOWN to properly terminate it.
            Log.i(LOG_TAG, "No running tunnels found")
            val t = sharedTunnel
            if (t != null && config != null) {
                Log.i(LOG_TAG, "Orphaned tunnel detected - bringing UP then DOWN to terminate")
                try {
                    backend.setState(t, Tunnel.State.UP, config)
                    Thread.sleep(100)
                    expectDown()
                    backend.setState(t, Tunnel.State.DOWN, config)
                    Log.i(LOG_TAG, "Tunnel brought DOWN - orphaned connection terminated")
                } catch (e: Exception) {
                    Log.e(LOG_TAG, "Error terminating orphaned tunnel: ${e.message}", e)
                }
            }
            return false
        }

        internal fun rememberContext(context: Context) {
            if (appContext == null) appContext = context.applicationContext
        }

        internal fun clearStatsFromStorage(context: Context) {
            context.getSharedPreferences("WireGuardStats", Context.MODE_PRIVATE).edit().clear().apply()
        }

        internal fun clearLastUsedConfig(context: Context) {
            context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE).edit()
                .remove("last_used_tunnel")
                .remove("last_used_config")
                .apply()
            sharedConfig = null
        }
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        // this.havePermission =
        //     (requestCode == PERMISSIONS_REQUEST_CODE) && (resultCode == Activity.RESULT_OK)
        // return havePermission
         if (requestCode == PERMISSIONS_REQUEST_CODE) {
        val granted = resultCode == Activity.RESULT_OK
        havePermission = granted
        vpnPermissionContinuation?.invoke(granted)
        vpnPermissionContinuation = null
        return true
        }
        return false
    }

    override fun onAttachedToActivity(activityPluginBinding: ActivityPluginBinding) {
        this.activity = activityPluginBinding.activity as FlutterActivity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        this.activity = null
    }

    override fun onReattachedToActivityForConfigChanges(activityPluginBinding: ActivityPluginBinding) {
        this.activity = activityPluginBinding.activity as FlutterActivity
    }

    override fun onDetachedFromActivity() {
        this.activity = null
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, METHOD_CHANNEL_NAME)
        events = EventChannel(flutterPluginBinding.binaryMessenger, METHOD_EVENT_NAME)
        trafficEvents = EventChannel(flutterPluginBinding.binaryMessenger, TRAFFIC_EVENT_NAME)
        context = flutterPluginBinding.applicationContext
        appContext = context
        instance = this

        channel.setMethodCallHandler(this)
        events.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                isVpnChecked = false
                vpnStageSink = events
            }

            override fun onCancel(arguments: Any?) {
                isVpnChecked = false
                vpnStageSink = null
            }
        })

       trafficEvents.setStreamHandler(object : EventChannel.StreamHandler {
        override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
           trafficSink = events

            scope.launch(Dispatchers.IO) {
              val isActive = isVpnActive()
              Log.i(TAG, "VPN active on trafficEvent listen: $isActive")
              if (isActive) {
                startTrafficMonitor()
              } else {
                stopTrafficMonitor()
              }
            }
        }

        override fun onCancel(arguments: Any?) {
         trafficSink = null
         stopTrafficMonitor()
        }
        }) 

     
            // Initialize backend async, then restore tunnel/config
    scope.launch(Dispatchers.IO) {
        try {
            backend = createBackend()
            futureBackend.complete(backend!!)

             // Now it's safe to access runningTunnelNames
            val runningTunnels = backend!!.runningTunnelNames
            Log.i(TAG, "Running tunnels after reopen: $runningTunnels")

            // After backend is ready, restore saved config (but don't auto-reconnect)
        val prefs = context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE)
val savedTunnelName = prefs.getString("last_used_tunnel", null)
val savedConfigString = prefs.getString("last_used_config", null)

if (!savedTunnelName.isNullOrEmpty() && !savedConfigString.isNullOrEmpty()) {
    try {
        val parsed = com.wireguard.config.Config.parse(savedConfigString.byteInputStream())
        if (parsed != null) {
            tunnelName = savedTunnelName
            config = parsed
            Log.i(TAG, "Restored last used tunnel and config (not auto-connecting)")
        } else {
            Log.e(TAG, "Parsed config is null")
        }
    } catch (e: Exception) {
        Log.e(TAG, "Failed to parse saved config: ${e.message}", e)
    }
}



            // Update stage/state after restoring
            val isActive = isVpnActive()
            
            // If VPN is active and we have restored config, register tunnel with backend
            // This allows disconnect to work without creating a new TUN interface
            if (isActive && !savedTunnelName.isNullOrEmpty() && config != null) {
                try {
                    // Only register if backend reports running tunnels
                    val runningTunnels = backend!!.runningTunnelNames
                    if (runningTunnels.isNotEmpty()) {
                        // Reset tunnel singleton to ensure fresh creation
                        tunnel = null
                        
                        // Create tunnel object to register with backend
                        val tunnelObj = tunnel(savedTunnelName) { state ->
                            updateStageFromState(state)
                        }
                        
                        Log.i(TAG, "Tunnel object recreated for existing VPN connection")
                        updateStage("connected")
                        
                        // Resume traffic monitoring and foreground service
                        startForegroundService()
                        startTrafficMonitor()
                    } else {
                        // System reports VPN active but backend has no tunnels
                        // This can happen briefly after disconnect
                        updateStage("disconnected")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to recreate tunnel object: ${e.message}", e)
                    updateStage("disconnected")
                }
            } else if (KillSwitchVpnService.isRunning) {
                updateStage("blocked")
            } else {
                updateStage(if (isActive) "connected" else "disconnected")
            }



        } catch (e: Exception) {
            Log.e(TAG, "Error initializing backend or restoring config", e)
        }
    }



    }
   

    private fun createBackend(): Backend {
        if (backend == null) {
            backend = GoBackend(context.applicationContext)
        }
        return backend as Backend
    }

    private fun flutterSuccess(result: Result, o: Any) {
        scope.launch(Dispatchers.Main) {
            result.success(o)
        }
    }

    private fun flutterError(result: Result, error: String) {
        scope.launch(Dispatchers.Main) {
            result.error(error, null, null)
        }
    }

    private fun flutterNotImplemented(result: Result) {
        scope.launch(Dispatchers.Main) {
            result.notImplemented()
        }
    }

    override fun onMethodCall(call: MethodCall, result: Result) {

        when (call.method) {
            "initialize" -> setupTunnel(
                call.argument<String>("localizedDescription").toString(),
                call.argument<String>("vpnName") ?: "WireGuard VPN",
                result
            )
            "checkVpnPermission" -> {
                checkAndRequestVpnPermission(result)
            }
            "start" -> {
                val wgQuickConfig = call.argument<String>("wgQuickConfig").toString()
                val excludedApps = call.argument<String>("excludedApps")
                val includedApps = call.argument<String>("includedApps")
                
                var finalConfig = wgQuickConfig
                if (!excludedApps.isNullOrEmpty()) {
                    finalConfig = finalConfig.replaceFirst(
                        Regex("(?i)\\[Interface\\]"),
                        "[Interface]\nExcludedApplications = $excludedApps"
                    )
                }
                if (!includedApps.isNullOrEmpty()) {
                    finalConfig = finalConfig.replaceFirst(
                        Regex("(?i)\\[Interface\\]"),
                        "[Interface]\nIncludedApplications = $includedApps"
                    )
                }

                connect(finalConfig, result)

                if (!isVpnChecked) {
        scope.launch(Dispatchers.IO) {
            val active = isVpnActive()
            state = if (active) "connected" else "disconnected"
            isVpnChecked = true
            println("VPN is ${if (active) "active" else "not active"}")
        }
    }
            }
            "stop" -> {
                disconnect(result)
            }
            "stage" -> {
                // Ask the backend (truth survives process restarts); fall back to the cached stage while it initialises.
                // A live kill-switch block reports "blocked" whenever no tunnel is up.
                val b = backend
                if (b != null && sharedTunnelName != null) {
                    scope.launch(Dispatchers.IO) {
                        val up = try { b.runningTunnelNames.contains(tunnelName) } catch (e: Throwable) { false }
                        val s = when {
                            up -> "connected"
                            KillSwitchVpnService.isRunning || state == "blocked" -> "blocked"
                            state == "connecting" || state == "prepare" || state == "disconnecting" -> state
                            else -> "disconnected"
                        }
                        state = s
                        withContext(Dispatchers.Main) { result.success(s) }
                    }
                } else {
                    result.success(if (KillSwitchVpnService.isRunning) "blocked" else getStatus())
                }
            }
            "setKillSwitch" -> {
                val enabled = call.argument<Boolean>("enabled") ?: false
                setKillSwitchEnabled(context, enabled)
                result.success(null)
            }
            "getKillSwitch" -> result.success(isKillSwitchEnabled(context))
            "clearBlock" -> {
                clearBlock(context)
                result.success(null)
            }
            "checkPermission" -> {
                checkPermission()
                result.success(null)
            }
            "getDownloadData" -> {
                getDownloadData(result)
            }
        "getUploadData" -> {
            getUploadData(result)
        }
        
            else -> flutterNotImplemented(result)
        }
    }

    private fun isVpnActive(): Boolean {
        try {
            val connectivityManager =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = connectivityManager.activeNetwork
                val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                return networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            } else {
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "isVpnActive - ERROR - ${e.message}")
            return false
        }
    }




    internal fun updateStage(stage: String?) {
        scope.launch(Dispatchers.Main) {
            val updatedStage = stage ?: "no_connection"
            state = updatedStage
            vpnStageSink?.success(updatedStage.lowercase(Locale.ROOT))
        }
    }

    internal fun updateStageFromState(state: Tunnel.State) {
        scope.launch(Dispatchers.Main) {
            when (state) {
                Tunnel.State.UP -> updateStage("connected")
                Tunnel.State.DOWN -> updateStage(if (WireguardFlutterPlugin.state == "blocked") "blocked" else "disconnected")
                else -> updateStage("wait_connection")
            }
        }
    }
private fun connect(wgQuickConfig: String, result: Result) {
    checkAndRequestVpnPermissionBlocking { granted ->
        if (!granted) {
            result.error("PERMISSION_DENIED", "User denied VPN permission", null)
            return@checkAndRequestVpnPermissionBlocking
        }
        scope.launch(Dispatchers.IO) {
            try {
                if (!havePermission) {
                    checkPermission()
                    throw Exception("Permissions are not given")
                }
                
                // Check if tunnel is already UP to avoid disconnect-then-connect cycle
                // But only if we have a valid tunnel object (not after a disconnect where we nullified it)
                val backend = futureBackend.await()
                // Only one VPN can be active: a kill-switch block must be gone before the tunnel establishes.
                clearBlock(context)
                val runningTunnels = backend.runningTunnelNames

                val inputStream = ByteArrayInputStream(wgQuickConfig.toByteArray())
                val parsedConfig = com.wireguard.config.Config.parse(inputStream)
                    ?: throw Exception("Failed to parse WireGuard config")

                if (runningTunnels.contains(tunnelName)) {
                    val sameConfig = config != null && config.toString() == parsedConfig.toString()
                    if (sameConfig) {
                        // Identical config already up (e.g. the app was reopened while the service kept the tunnel): adopt it.
                        Log.i(TAG, "Tunnel $tunnelName is already UP with the same config, adopting")
                        config = parsedConfig
                        startForegroundService()
                        startTrafficMonitor()
                        updateStage("connected")
                        withContext(Dispatchers.Main) { flutterSuccess(result, "") }
                        return@launch
                    }
                    // Different config (new peer/keys): the old tunnel MUST go down first or the new keys never apply.
                    Log.i(TAG, "Tunnel $tunnelName is UP with a different config, restarting it")
                    updateStage("disconnecting")
                    expectDown()
                    backend.setState(tunnel(tunnelName), Tunnel.State.DOWN, null)
                    tunnel = null
                }

                updateStage("prepare")

                updateStage("connecting")

                backend.setState(
                    tunnel(tunnelName) { state ->
                        scope.launch(Dispatchers.Main) {
                            Log.i(TAG, "onStateChange - $state")
                            updateStageFromState(state)
                        }
                    },
                    Tunnel.State.UP,
                    parsedConfig
                )
                config = parsedConfig

                withContext(Dispatchers.IO) {
                    //saveLastUsedConfig(tunnelName, parsedConfig)
                    saveLastUsedConfig(tunnelName, wgQuickConfig)
                }

                Log.i(TAG, "Connect - success!")
                startForegroundService()
                startTrafficMonitor()

                withContext(Dispatchers.Main) {
                    flutterSuccess(result, "")
                }
            } catch (e: BackendException) {
                Log.e(TAG, "Connect - BackendException - ERROR - ${e.reason}", e)
                withContext(Dispatchers.Main) {
                    flutterError(result, e.reason.toString())
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Connect - Can't connect to tunnel: $e", e)
                withContext(Dispatchers.Main) {
                    flutterError(result, e.message.toString())
                }
            }
        }
    }
}


private fun disconnect(result: Result) {
    trafficMonitorActive = false
    connectionStartTime = 0L

    scope.launch(Dispatchers.IO) {
        try {
            val backend = futureBackend.await()
            Log.i(TAG, "Current Config: $config")
            updateStage("disconnecting")

            // Stop traffic monitor and reset stats BEFORE bringing the tunnel down
            stopTrafficMonitor()
            resetTrafficStats()

            val hadRunning = tearDownTunnel(context, backend) { state ->
                scope.launch(Dispatchers.Main) {
                    Log.i(TAG, "onStateChange - $state")
                    if (state == Tunnel.State.DOWN) {
                        resetTrafficStats()
                        stopTrafficMonitor()
                    }
                    updateStageFromState(state)
                }
            }

            // Wait for state change to propagate
            if (hadRunning) delay(1000)

            // Explicitly update stage to disconnected
            updateStage("disconnected")

            stopForegroundService()
            clearStatsFromStorage()
            deleteActiveTunnel()

            // Nullify tunnel object to ensure clean state
            tunnel = null
            config = null
            Log.i(TAG, "Tunnel object and config nullified")

            Log.i(TAG, "Disconnected successfully.")
            withContext(Dispatchers.Main) {
                flutterSuccess(result, "")
            }
        } catch (e: BackendException) {
            Log.e(TAG, "BackendException during disconnect: ${e.reason}", e)
            // Even on error, nullify tunnel to prevent ghost connections
            tunnel = null
            config = null
            withContext(Dispatchers.Main) {
                flutterError(result, e.reason.toString())
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Exception during disconnect: ${e.message}", e)
            // Even on error, nullify tunnel to prevent ghost connections
            tunnel = null
            config = null
            withContext(Dispatchers.Main) {
                flutterError(result, e.message.toString())
            }
        }
    }
}




 internal fun resetTrafficStats() {
    VpnTrafficStats.uploadSpeed = "0.0 KB/s"
    VpnTrafficStats.downloadSpeed = "0.0 KB/s"
    VpnTrafficStats.duration = "00:00:00"

    // ✅ Must run on main thread to send to Flutter
    scope.launch(Dispatchers.Main) {
        trafficSink?.success(
            mapOf(
                "totalDownload" to 0,
                "totalUpload" to 0,
                "downloadSpeed" to 0,
                "uploadSpeed" to 0,
                "duration" to "00:00:00"
            )
        )
    }
    // Don't nullify trafficSink here - let the EventChannel's onCancel handle it
    // This allows traffic monitoring to continue working after reconnection
 }

  private fun clearStatsFromStorage() = clearStatsFromStorage(context)


    private fun setupTunnel(localizedDescription: String, vpnName: String, result: Result) {
        scope.launch(Dispatchers.IO) {
            if (Tunnel.isNameInvalid(localizedDescription)) {
                flutterError(result, "Invalid Name")
                return@launch
            }
            tunnelName = localizedDescription
            vpnDisplayName = vpnName // Store the custom VPN name

            checkPermission()
            // If the tunnel is already running (app reopened while the foreground service kept it up), adopt it now so
            // stage() answers "connected" immediately and traffic stats resume for the new engine.
            try {
                val b = futureBackend.await()
                if (b.runningTunnelNames.contains(tunnelName)) {
                    if (config == null) {
                        val prefs = context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE)
                        prefs.getString("last_used_config", null)?.let { config = com.wireguard.config.Config.parse(it.byteInputStream()) }
                    }
                    state = "connected"
                    startTrafficMonitor()
                    updateStage("connected")
                } else if (KillSwitchVpnService.isRunning) {
                    state = "blocked"
                    updateStage("blocked")
                }
            } catch (e: Throwable) {
                Log.w(TAG, "initialize: could not check running tunnels: ${e.message}")
            }
            result.success(null)
        }
    }

    // Non-interactive: only records whether the VPN permission exists. The system prompt is shown by
    // checkAndRequestVpnPermissionBlocking() when the user actually connects — never at initialize().
    private fun checkPermission() {
        val intent = try { VpnService.prepare(context) } catch (e: Throwable) { null }
        havePermission = intent == null
    }
    private fun checkAndRequestVpnPermission(result: MethodChannel.Result) {
        val intent = VpnService.prepare(context)
        if (intent != null) {
            // Permission NOT granted yet, ask user by launching system dialog
            permissionResult = result
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity?.startActivityForResult(intent, PERMISSIONS_REQUEST_CODE)
                ?: run {
                    // If activity is null, cannot request permission properly
                    result.error("NO_ACTIVITY", "Activity is null, cannot request VPN permission", null)
                }
        } else {
            // Permission already granted
            havePermission = true
            result.success(true)
        }
    }

    fun checkAndRequestVpnPermissionBlocking(callback: (Boolean) -> Unit) {
     val intent = VpnService.prepare(context)
      if (intent != null) {
        vpnPermissionContinuation = callback
        activity?.startActivityForResult(intent, PERMISSIONS_REQUEST_CODE)
      } else {
        // Already granted
        havePermission = true
        callback(true)
     }
    }

    private fun getDownloadData(result: Result) {
     scope.launch(Dispatchers.IO) {
        try {
            val stats = futureBackend.await().getStatistics(tunnel(tunnelName))
            val downloadData = stats.totalRx() // Use totalRx() instead of totalRx
            flutterSuccess(result, downloadData)
        } catch (e: Throwable) {
            Log.e(TAG, "getDownloadData - ERROR - ${e.message}")
            flutterError(result, e.message.toString())
        }
     }
    }

     private fun getUploadData(result: Result) {
       scope.launch(Dispatchers.IO) {
        try {
            val stats = futureBackend.await().getStatistics(tunnel(tunnelName))
            val uploadData = stats.totalTx() // Use totalTx() instead of totalTx
            flutterSuccess(result, uploadData)
        } catch (e: Throwable) {
            Log.e(TAG, "getUploadData - ERROR - ${e.message}")
            flutterError(result, e.message.toString())
        }
      }
    }

    private fun getDataCounts(result: Result) {
        scope.launch(Dispatchers.IO) {
        try {
            val stats = futureBackend.await().getStatistics(tunnel(tunnelName))
            val dataCounts = mapOf(
                "download" to stats.totalRx(),
                "upload" to stats.totalTx()
            )
            flutterSuccess(result, dataCounts)
        } catch (e: Throwable) {
            Log.e(TAG, "getDataCounts - ERROR - ${e.message}")
            flutterError(result, e.message.toString())
        }
    }
    }

  private fun startTrafficMonitor() {
    if (sharedTunnelName == null) {
        Log.e("NVPN", "Tunnel name has not been initialized!")
        return
    }

    val prefs = context.getSharedPreferences("WireGuardStats", Context.MODE_PRIVATE)

    // For fresh connections, reset the start time. For app restarts, restore it.
    val savedStartTime = prefs.getLong("connectionStartTime", 0L)
    connectionStartTime = if (savedStartTime == 0L || !isVpnActive()) {
        System.currentTimeMillis()
    } else {
        savedStartTime
    }
    
    previousRx = prefs.getLong("totalRx", 0)
    previousTx = prefs.getLong("totalTx", 0)
    lastUpdateTime = 0L  // Always reset to 0 for fresh monitoring
    
    trafficMonitorActive = true
    

    scope.launch(Dispatchers.IO) {
        while (trafficMonitorActive) {
            try {
                val currentTime = System.currentTimeMillis()

                val stats = futureBackend.await().getStatistics(tunnel(tunnelName))
                val currentRx = stats.totalRx()
                val currentTx = stats.totalTx()

                // Calculate speeds (0 on first iteration)
                val timeDiff = if (lastUpdateTime != 0L) {
                    (currentTime - lastUpdateTime) / 1000.0
                } else {
                    1.0 // Use 1 second as default to avoid division by zero
                }
                
                val downloadSpeed = if (lastUpdateTime != 0L) {
                    (currentRx - previousRx) / timeDiff
                } else {
                    0.0 // First iteration, no speed yet
                }
                
                val uploadSpeed = if (lastUpdateTime != 0L) {
                    (currentTx - previousTx) / timeDiff
                } else {
                    0.0 // First iteration, no speed yet
                }

                // Calculate duration
                val elapsedMillis = currentTime - connectionStartTime
                val elapsedSeconds = (elapsedMillis / 1000) % 60
                val elapsedMinutes = (elapsedMillis / (1000 * 60)) % 60
                val elapsedHours = (elapsedMillis / (1000 * 60 * 60))
                val durationString = String.format("%02d:%02d:%02d", elapsedHours, elapsedMinutes, elapsedSeconds)

                VpnTrafficStats.uploadSpeed = String.format("%.1f KB/s", uploadSpeed / 1024)
                VpnTrafficStats.downloadSpeed = String.format("%.1f KB/s", downloadSpeed / 1024)
                VpnTrafficStats.duration = durationString

                // Always send data, even on first iteration
                val data = mapOf(
                    "totalDownload" to (currentRx / 1024),
                    "totalUpload" to (currentTx / 1024),
                    "downloadSpeed" to (downloadSpeed / 1024),
                    "uploadSpeed" to (uploadSpeed / 1024),
                    "duration" to durationString
                )

                scope.launch(Dispatchers.Main) {
                    trafficSink?.success(data)
                }

                // Save values persistently
                prefs.edit().apply {
                    putLong("totalRx", currentRx)
                    putLong("totalTx", currentTx)
                    putLong("lastUpdateTime", currentTime)
                    putLong("connectionStartTime", connectionStartTime)
                    apply()
                }

                previousRx = currentRx
                previousTx = currentTx
                lastUpdateTime = currentTime

                delay(1000)
            } catch (e: Throwable) {
                Log.e("NVPN", "Traffic monitor error: ${e.message}")
                delay(2000)
            }
        }
    }
  }


   internal fun stopTrafficMonitor() {
        trafficMonitorActive = false
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        if (instance === this) instance = null
        channel.setMethodCallHandler(null)
        events.setStreamHandler(null)
        trafficEvents.setStreamHandler(null)
        // The tunnel keeps running in the foreground service; only the Dart side is gone.
        // Drop the sinks so nothing is sent to a detached engine; a new engine re-registers via onListen.
        vpnStageSink = null
        trafficSink = null
        stopTrafficMonitor()
        isVpnChecked = false
    }

    private fun tunnel(name: String, callback: StateChangeCallback? = null): WireGuardTunnel {
        if (tunnel == null) {
            tunnel = WireGuardTunnel(name, callback)
        }
        return tunnel as WireGuardTunnel
    }







   private fun startForegroundService() = VpnForegroundService.start(context, vpnDisplayName)

  private fun stopForegroundService() = VpnForegroundService.stop(context)


private fun saveLastUsedConfig(name: String, wgQuickString: String) {
    val sharedPreferences = context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE)
    val editor = sharedPreferences.edit()
    editor.putString("last_used_tunnel", name)
    editor.putString("last_used_config", wgQuickString)
    editor.apply()
    Log.i(TAG, "Saved last used tunnel: $name")
    Log.i(TAG, "Saved config string:\n$wgQuickString")
}


private fun deleteActiveTunnel() = clearLastUsedConfig(context)



private fun Config.toWgQuickString(): String {
    return WgQuickConfig.toWgQuickString(this)
}

}

typealias StateChangeCallback = (Tunnel.State) -> Unit

class WireGuardTunnel(
    private val name: String, private val onStateChanged: StateChangeCallback? = null
) : Tunnel {

    override fun getName() = name

    override fun onStateChange(newState: Tunnel.State) {
        // Kill switch first: an unexpected DOWN sets state = "blocked" before the per-call callback maps the stage.
        WireguardFlutterPlugin.onTunnelState(newState)
        onStateChanged?.invoke(newState)
    }
}

object VpnTrafficStats {
    var uploadSpeed: String = "0 KB/s"
    var downloadSpeed: String = "0 KB/s"
    var duration: String = "00:00:00" // Initialize duration
}



/**
 * Keeps the process (and the tunnel) alive while the app UI is closed and owns the persistent notification:
 * title = vpnDisplayName, "Connected · tap to open", content intent = the app's launch activity, action "Disconnect".
 * Android 8+: channel; 13+: the app must hold POST_NOTIFICATIONS or the notification is hidden (service still runs);
 * 14+: foregroundServiceType connectedDevice is declared in the manifest.
 */
class VpnForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "vpn_foreground_channel"
        const val NOTIFICATION_ID = 101
        const val ACTION_START = "START"
        const val ACTION_STOP = "STOP"
        const val EXTRA_DISPLAY_NAME = "vpnDisplayName"
        private const val PREF_DISPLAY_NAME = "vpn_display_name"
        private const val LOG_TAG = "NVPN"

        fun start(context: Context, displayName: String) {
            context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE).edit().putString(PREF_DISPLAY_NAME, displayName).apply()
            val intent = Intent(context, VpnForegroundService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_DISPLAY_NAME, displayName)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Throwable) {
                Log.e(LOG_TAG, "startForegroundService failed: ${e.message}", e)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, VpnForegroundService::class.java).setAction(ACTION_STOP)
            try {
                context.startService(intent)
            } catch (e: Throwable) {
                // Background start restriction (service not running): stopService is always allowed and removes the notification.
                try { context.stopService(intent) } catch (t: Throwable) { Log.e(LOG_TAG, "stopService failed: ${t.message}") }
            }
        }

        private fun pendingIntentFlags(): Int {
            var flags = PendingIntent.FLAG_UPDATE_CURRENT
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags = flags or PendingIntent.FLAG_IMMUTABLE
            return flags
        }
    }

    private var vpnDisplayName: String = "WireGuard VPN"

    override fun onCreate() {
        super.onCreate()
        WireguardFlutterPlugin.rememberContext(applicationContext)
        vpnDisplayName = getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE).getString(PREF_DISPLAY_NAME, null) ?: vpnDisplayName
        createNotificationChannel()
        promote(buildNotification())
    }

    private fun promote(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN Service", NotificationManager.IMPORTANCE_LOW)
            channel.setShowBadge(false)
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    /** The app's own icon: `drawable/ic_notification` when the app ships one, else its launcher icon, else a lock. */
    private fun smallIconRes(): Int {
        val custom = resources.getIdentifier("ic_notification", "drawable", packageName)
        if (custom != 0) return custom
        val appIcon = applicationInfo.icon
        return if (appIcon != 0) appIcon else android.R.drawable.ic_lock_lock
    }

    private fun buildNotification(): Notification {
        val flags = pendingIntentFlags()
        val launch = packageManager.getLaunchIntentForPackage(packageName)
            ?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val contentIntent = launch?.let { PendingIntent.getActivity(this, 0, it, flags) }
        val disconnectIntent = PendingIntent.getBroadcast(
            this, 1,
            Intent(this, VpnDisconnectReceiver::class.java).setAction(WireguardFlutterPlugin.ACTION_DISCONNECT),
            flags
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(vpnDisplayName)
            .setContentText("Connected · tap to open")
            .setSmallIcon(smallIconRes())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectIntent)
        if (contentIntent != null) builder.setContentIntent(contentIntent)
        return builder.build()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                vpnDisplayName = intent.getStringExtra(EXTRA_DISPLAY_NAME) ?: vpnDisplayName
                promote(buildNotification())
            }
            ACTION_STOP -> {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        try { ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

/** Target of the notification "Disconnect" action. Runs in the plugin process; no Flutter engine required. */
class VpnDisconnectReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == WireguardFlutterPlugin.ACTION_KILL_SWITCH_OFF) {
            Log.i("NVPN", "Kill switch turned off from notification")
            WireguardFlutterPlugin.setKillSwitchEnabled(context.applicationContext, false)
            return
        }
        if (intent.action != WireguardFlutterPlugin.ACTION_DISCONNECT) return
        Log.i("NVPN", "Disconnect requested from notification")
        val pending = goAsync()
        WireguardFlutterPlugin.disconnectFromNotification(context.applicationContext) {
            try { pending.finish() } catch (_: Throwable) {}
        }
    }
}
