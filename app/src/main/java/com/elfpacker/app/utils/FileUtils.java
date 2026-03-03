package com.elfpacker.app.utils;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 文件操作工具类
 */
public class FileUtils {

    /**
     * 从 Uri 复制文件到应用私有缓存目录
     * Android 10+ 需要通过 ContentResolver 访问外部文件
     */
    public static File copyUriToCache(Context context, Uri uri) throws IOException {
        String fileName = getFileName(context, uri);
        if (fileName == null) fileName = "input_elf_" + System.currentTimeMillis();

        File cacheDir = context.getCacheDir();
        File destFile = new File(cacheDir, fileName);

        try (InputStream is = context.getContentResolver().openInputStream(uri);
             OutputStream os = new FileOutputStream(destFile)) {
            if (is == null) throw new IOException("无法打开文件流");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                os.write(buffer, 0, read);
            }
        }
        return destFile;
    }

    /**
     * 从 Uri 获取文件名
     */
    public static String getFileName(Context context, Uri uri) {
        String result = null;
        if ("content".equals(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(
                    uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (idx >= 0) result = cursor.getString(idx);
                }
            }
        }
        if (result == null) result = uri.getLastPathSegment();
        return result;
    }

    /**
     * 获取或创建加壳输出目录
     * 输出路径：/sdcard/Android/data/<packageName>/files/packed/
     */
    public static File getOutputDir(Context context) {
        File outDir = new File(context.getExternalFilesDir(null), "packed");
        if (!outDir.exists()) outDir.mkdirs();
        return outDir;
    }

    /**
     * 格式化文件大小（B / KB / MB）
     */
    public static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024f);
        return String.format("%.2f MB", bytes / (1024f * 1024f));
    }

    /**
     * 写字节数组到文件
     */
    public static void writeFile(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
}