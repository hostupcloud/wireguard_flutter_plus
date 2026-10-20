package orban.group.wireguard_flutter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Kill switch: a lightweight blocking VPN session that black-holes all traffic while the WireGuard tunnel is down.
 *
 * Android allows exactly one VPN per device, so this service is only started after the tunnel is confirmed DOWN
 * ([WireguardFlutterPlugin.onTunnelState]) and is always released before the tunnel is brought UP again
 * ([WireguardFlutterPlugin.clearBlock] / the "start" method). If another VPN takes over while we block, the system
 * calls [onRevoke] and we simply let go.
 *
 * The TUN device is never read, so every packet routed into it (0.0.0.0/0 and ::/0, plus a DNS server inside the
 * same black hole so lookups cannot leak to the underlying network's resolver) is dropped. Nothing is excluded, the
 * app itself included: the Dart side must call `clearBlock` before it talks to the control plane.
 *
 * Foreground notification: "Kill switch active · tap to reconnect" (tap opens the app, action turns the kill switch
 * off). Same service type / permission pattern as [VpnForegroundService]; when promoting to foreground is refused
 * (background-start rules on Android 12+), the block still stands and a plain notification is posted instead.
 */
class KillSwitchVpnService : VpnService() {

    companion object {
        const val CHANNEL_ID = "vpn_kill_switch_channel"
        const val NOTIFICATION_ID = 102
        const val ACTION_BLOCK = "BLOCK"
        const val ACTION_UNBLOCK = "UNBLOCK"
        private const val LOG_TAG = "NVPN"

        /** True while the blocking VPN session is established. */
        @Volatile
        var isRunning: Boolean = false
            private set

        @Volatile
        private var current: KillSwitchVpnService? = null

        /** Starts the block. Safe to call when it is already up (no-op). */
        fun start(context: Context) {
            val app = context.applicationContext
            val intent = Intent(app, KillSwitchVpnService::class.java).setAction(ACTION_BLOCK)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) app.startForegroundService(intent) else app.startService(intent)
            } catch (e: Throwable) {
                // Foreground start refused (Android 12+ background rules): a plain start still works while the tunnel's
                // own foreground service is alive, and the block does not depend on being foreground.
                Log.w(LOG_TAG, "Kill switch: startForegroundService refused (${e.message}); falling back to startService")
                try { app.startService(intent) } catch (t: Throwable) { Log.e(LOG_TAG, "Kill switch: could not start block service: ${t.message}", t) }
            }
        }

        /**
         * Releases the block immediately (closes the TUN fd synchronously, so the next `establish()` of the real tunnel
         * cannot race it) and stops the service.
         */
        fun stop(context: Context) {
            current?.release()
            val app = context.applicationContext
            val intent = Intent(app, KillSwitchVpnService::class.java).setAction(ACTION_UNBLOCK)
            try {
                app.startService(intent)
            } catch (e: Throwable) {
                try { app.stopService(intent) } catch (t: Throwable) { Log.e(LOG_TAG, "Kill switch: stopService failed: ${t.message}") }
            }
        }

        private fun pendingIntentFlags(): Int {
            var flags = PendingIntent.FLAG_UPDATE_CURRENT
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags = flags or PendingIntent.FLAG_IMMUTABLE
            return flags
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var foreground = false

    override fun onCreate() {
        super.onCreate()
        current = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_UNBLOCK -> {
                release()
                dismiss()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                // ACTION_BLOCK, or null = sticky restart after the process died while blocking: re-engage only if the
                // user still wants the kill switch.
                if (intent == null && !WireguardFlutterPlugin.isKillSwitchEnabled(this)) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                promote()
                engage()
                return START_STICKY
            }
        }
    }

    private fun engage() {
        if (tun != null) return
        try {
            if (prepare(this) != null) {
                // VPN consent was revoked for this package: nothing we can block with.
                Log.e(LOG_TAG, "Kill switch: VPN permission missing, cannot block")
                fail()
                return
            }
            val builder = Builder()
                .setSession("Kill switch")
                .setMtu(1280)
                .addAddress("10.255.255.1", 32)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                // Resolver inside the black hole: without any DNS server Android would send lookups to the underlying
                // network's resolver and leak every hostname.
                .addDnsServer("10.255.255.2")
                .setBlocking(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            val fd = builder.establish()
            if (fd == null) {
                Log.e(LOG_TAG, "Kill switch: establish() returned null")
                fail()
                return
            }
            tun = fd
            isRunning = true
            Log.i(LOG_TAG, "Kill switch: all traffic blocked")
            WireguardFlutterPlugin.onBlockEngaged()
        } catch (e: Throwable) {
            Log.e(LOG_TAG, "Kill switch: establish failed: ${e.message}", e)
            fail()
        }
    }

    private fun fail() {
        release()
        dismiss()
        WireguardFlutterPlugin.onBlockReleased(failed = true)
        stopSelf()
    }

    /** Closes the TUN device (ends the VPN session). Idempotent, callable from any thread. */
    internal fun release() {
        val fd = tun ?: return
        tun = null
        isRunning = false
        try { fd.close() } catch (_: Throwable) {}
        Log.i(LOG_TAG, "Kill switch: block released")
    }

    /** Another VPN (ours coming back up, or a different app) took the slot: the block is gone, say so. */
    override fun onRevoke() {
        Log.i(LOG_TAG, "Kill switch: revoked by the system")
        release()
        dismiss()
        WireguardFlutterPlugin.onBlockReleased(failed = false)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        release()
        dismiss()
        if (current === this) current = null
        super.onDestroy()
    }

    // --- notification -------------------------------------------------------------------------------------------

    private fun promote() {
        val notification = buildNotification()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            foreground = true
        } catch (e: Throwable) {
            // ForegroundServiceStartNotAllowedException and friends: keep the block, show a normal notification.
            Log.w(LOG_TAG, "Kill switch: startForeground refused (${e.message}); posting a plain notification")
            try { getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, notification) } catch (_: Throwable) {}
        }
    }

    private fun dismiss() {
        if (foreground) {
            foreground = false
            try { ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
        }
        try { getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID) } catch (_: Throwable) {}
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Kill switch", NotificationManager.IMPORTANCE_DEFAULT)
            channel.setShowBadge(false)
            channel.setSound(null, null)
            channel.enableVibration(false)
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    /** Same icon rule as [VpnForegroundService]: the app's `drawable/ic_notification`, else its launcher icon. */
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
        val contentIntent = launch?.let { PendingIntent.getActivity(this, 2, it, flags) }
        val offIntent = PendingIntent.getBroadcast(
            this, 3,
            Intent(this, VpnDisconnectReceiver::class.java).setAction(WireguardFlutterPlugin.ACTION_KILL_SWITCH_OFF),
            flags
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Kill switch active")
            .setContentText("Connection dropped · tap to reconnect")
            .setSmallIcon(smallIconRes())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Turn off kill switch", offIntent)
        if (contentIntent != null) builder.setContentIntent(contentIntent)
        return builder.build()
    }
}
