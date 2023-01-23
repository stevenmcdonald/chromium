package org.chromium.chrome.browser;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.SystemClock;

import androidx.core.app.NotificationCompat;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class ShadowsocksService extends Service {
    public ShadowsocksService() {}

    @Override
    public void onCreate() {
        final String nativeLibraryDir = getApplicationInfo().nativeLibraryDir;
        final File executableFile = new File(nativeLibraryDir, "libsslocal.so");
        final String executablePath = executableFile.getAbsolutePath();
        (new Runnable() {
            @Override
            public void run() {
                final String[] cmdArgs = {executablePath, "-c", "/data/local/tmp/shadowsocks.conf"};
                try {
                    Runtime.getRuntime().exec(cmdArgs);
                } catch (IOException e) {
                    android.util.Log.e("shadow-exec3", Arrays.toString(cmdArgs), e);
                }
            }
        }).run();
        super.onCreate();
    }

    @Override
    @SuppressLint("NewApi")
    public int onStartCommand(Intent intent, int flags, int startId) {
        String channelId = "shadowsocks-channel";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            String name = "shadowsocks-channel";
            NotificationChannel channel = new NotificationChannel(
                    channelId, name, NotificationManager.IMPORTANCE_DEFAULT);
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
        Intent notificationIntent = new Intent(this, ChromeTabbedActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, 0);

        Notification notification =
                new NotificationCompat.Builder(this, channelId)
                        .setAutoCancel(false)
                        .setOngoing(true)
                        .setContentTitle("Shadowsocks in running")
                        .setContentText("Shadowsocks in running within Chromium")
                        .setContentIntent(pendingIntent)
                        .setPriority(Notification.PRIORITY_HIGH)
                        .setTicker("Shadowsocks in running within Chromium")
                        .build();

        startForeground((int) SystemClock.uptimeMillis(), notification);

        // return super.onStartCommand(intent, flags, startId);
        return Service.START_REDELIVER_INTENT;
    }

    @Override
    public IBinder onBind(Intent intent) {
        // TODO: Return the communication channel to the service.
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
