package com.elfpacker.app.protector;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * 资源文件混淆保护（Assets Obfuscation）
 *
 * <p>对 APK 中 {@code assets/} 目录下的每个文件执行以下操作：</p>
 * <ol>
 *   <li>生成随机 8 字符十六进制名称替换原始文件名（扩展名保留）</li>
 *   <li>对文件内容进行逐字节 XOR 加密（随机 16 字节密钥）</li>
 *   <li>将原始路径 → 混淆路径的映射和密钥写入 {@code META-INF/asset_map.bin}</li>
 * </ol>
 *
 * <p>映射文件格式（{@code asset_map.bin}）：</p>
 * <pre>
 *   [4B] entry count (LE uint32)
 *   For each entry:
 *     [2B] original path length (LE)
 *     [N B] original path (UTF-8)
 *     [2B] obfuscated path length (LE)
 *     [M B] obfuscated path (UTF-8)
 *     [16B] XOR key
 * </pre>
 */
public class AssetObfuscator implements ApkProtector {

    private static final int KEY_LEN = 16;

    @Override
    public void protect(File input, File output) throws IOException {
        SecureRandom rng = new SecureRandom();

        List<String> origPaths = new ArrayList<>();
        List<String> obfPaths  = new ArrayList<>();
        List<byte[]> keys      = new ArrayList<>();

        try (ZipFile zipIn = new ZipFile(input);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(output))) {

            zos.setMethod(ZipOutputStream.DEFLATED);

            Enumeration<? extends ZipEntry> entries = zipIn.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                byte[] data = readEntry(zipIn, entry);

                String outName = name;
                byte[] outData = data;

                if (name.startsWith("assets/") && !entry.isDirectory()) {
                    byte[] key = new byte[KEY_LEN];
                    rng.nextBytes(key);

                    String obfName = obfuscatePath(name, rng);
                    outData = xor(data, key);
                    outName = obfName;

                    origPaths.add(name);
                    obfPaths.add(obfName);
                    keys.add(key);
                }

                ZipEntry outEntry = new ZipEntry(outName);
                zos.putNextEntry(outEntry);
                zos.write(outData);
                zos.closeEntry();
            }

            // Write mapping file
            byte[] mapBytes = buildMapFile(origPaths, obfPaths, keys);
            ZipEntry mapEntry = new ZipEntry("META-INF/asset_map.bin");
            zos.putNextEntry(mapEntry);
            zos.write(mapBytes);
            zos.closeEntry();
        }
    }

    @Override
    public String getName() {
        return "资源文件混淆";
    }

    // -------------------------------------------------------------------------

    private static String obfuscatePath(String originalPath, SecureRandom rng) {
        // Keep "assets/" prefix and file extension
        String prefix = "assets/";
        String rest = originalPath.substring(prefix.length());
        int dotIdx = rest.lastIndexOf('.');
        String ext = dotIdx >= 0 ? rest.substring(dotIdx) : "";

        byte[] randBytes = new byte[4];
        rng.nextBytes(randBytes);
        StringBuilder sb = new StringBuilder(prefix);
        for (byte b : randBytes) sb.append(String.format("%02x", b));
        sb.append(ext);
        return sb.toString();
    }

    private static byte[] xor(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    private static byte[] buildMapFile(List<String> orig, List<String> obf, List<byte[]> keys)
            throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.nio.ByteBuffer countBuf = java.nio.ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        countBuf.putInt(orig.size());
        baos.write(countBuf.array());
        for (int i = 0; i < orig.size(); i++) {
            writeShortString(baos, orig.get(i));
            writeShortString(baos, obf.get(i));
            baos.write(keys.get(i));
        }
        return baos.toByteArray();
    }

    private static void writeShortString(java.io.ByteArrayOutputStream baos, String s)
            throws IOException {
        byte[] bytes = s.getBytes("UTF-8");
        java.nio.ByteBuffer lb = java.nio.ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);
        lb.putShort((short) bytes.length);
        baos.write(lb.array());
        baos.write(bytes);
    }

    private static byte[] readEntry(ZipFile zf, ZipEntry entry) throws IOException {
        try (InputStream is = zf.getInputStream(entry)) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
            return baos.toByteArray();
        }
    }
}
