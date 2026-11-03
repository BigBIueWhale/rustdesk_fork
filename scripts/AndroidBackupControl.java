package org.rustdesk.backupcontrol;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** Disposable positive control; no backup exclusions or custom backup agent. */
public final class AndroidBackupControl extends Activity {
    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            Context device = createDeviceProtectedStorageContext();
            seed("r", getDataDir());
            seed("f", getFilesDir());
            seed("db", getDatabasePath("unused").getParentFile());
            seed("sp", new File(getDataDir(), "shared_prefs"));
            seed("ef", getExternalFilesDir(null));
            seed("d_r", device.getDataDir());
            seed("d_f", device.getFilesDir());
            seed("d_db", device.getDatabasePath("unused").getParentFile());
            seed("d_sp", new File(device.getDataDir(), "shared_prefs"));
        } catch (Exception error) {
            throw new IllegalStateException("backup control fixture creation failed", error);
        }
    }

    private static void seed(String domain, File directory) throws Exception {
        if (directory == null || (!directory.isDirectory() && !directory.mkdirs())) {
            throw new IllegalStateException("backup domain unavailable: " + domain);
        }
        File file = new File(directory, "rd_backup_" + domain + ".xml");
        if (!file.createNewFile()) throw new IllegalStateException("fixture already exists");
        String value = "<map><string name=\"probe\">rustdesk-backup-" + domain + "</string></map>\n";
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(value.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
    }
}
